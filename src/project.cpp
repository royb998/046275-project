/*! @file
 *  This file contains an ISA-portable PIN tool for counting loop iterations
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <map>
#include <vector>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <typeinfo>
#include <unistd.h>
#include <values.h>

using namespace std;
using std::cerr;
using std::endl;
using std::string;
using std::map;
using std::ofstream;

/* ===================================================================== */
/* Constants                                                             */
/* ===================================================================== */

const float HOT_BRANCH_THRESH = 0.6;
const float HOT_CALL_THRESH = 0.6;
const int HOT_CALL_MIN_COUNT = 2;

const std::string branch_profile = "branch-count.csv";
const std::string rtn_profile = "rtn-count.csv";

/* ===================================================================== */
/* Types and Globals                                                     */
/* ===================================================================== */

typedef struct
{
    UINT64 count_seen;
    UINT64 count_taken;
    ADDRINT rtn_addr;
    string rtn_name;
    ADDRINT target_addr;
} branch_data;

map<ADDRINT, branch_data> branches;

map<ADDRINT, UINT64> rtn_ins_counts;
map<ADDRINT, UINT64> rtn_call_counts;
map<ADDRINT, map<ADDRINT, UINT64>> caller_count;
map<ADDRINT, ADDRINT> rtn_callers;

map<ADDRINT, ADDRINT> inlining_candidates;
map<ADDRINT, UINT64> rtn_inline_count;
map<ADDRINT, float> branch_heat;
map<ADDRINT, ADDRINT> reordering_targets;
set<ADDRINT> skipped_routines;

// For XED:
#if defined(TARGET_IA32E)
xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char * tc;
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct
{
    ADDRINT orig_ins_addr;
    ADDRINT new_ins_addr;
    ADDRINT orig_targ_addr;
    bool hasNewTargAddr;
    char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
    xed_category_enum_t category_enum;
    unsigned int size;
    int targ_map_entry;
    UINT64 inline_count;
} instr_map_t;

instr_map_t * instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;

// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct
{
    ADDRINT rtn_addr;
    USIZE rtn_size;
    int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
} translated_rtn_t;

translated_rtn_t * translated_rtn;
int translated_rtn_num = 0;

ADDRINT main_image_addr = 0;

/* ===================================================================== */
/* Configuration                                                         */
/* ===================================================================== */

KNOB <BOOL> prof_mode(KNOB_MODE_WRITEONCE, "pintool", "prof", "0",
                      "Run in profile mode");

KNOB <BOOL> opt_mode(KNOB_MODE_WRITEONCE, "pintool", "opt", "0",
                      "Run in optimization mode");

KNOB <BOOL> knob_debug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0",
                      "Add debug prints");

KNOB <BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
                        "verbose", "0", "Verbose run");

KNOB <BOOL> KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
                                   "dump_tc", "0", "Dump Translated Code");

KNOB <BOOL> KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
                                          "no_tc_commit", "0", "Do not commit translated code");

INT32 Usage()
{
    cerr << "This tool prints out information per loop it finds.\n"
            "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

void dump_all_image_instrs(IMG img)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

            // Open the RTN.
            RTN_Open( rtn );

            cerr << RTN_Name(rtn) << ":" << endl;

            for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {
                  cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
            }

            // Close the RTN.
            RTN_Close( rtn );
        }
    }
}

void dump_instr_from_xedd(xed_decoded_inst_t* xedd, ADDRINT address)
{
    // debug print decoded instr:
    char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime address for disassembly

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);

    cerr << hex << address << ": " << disasm_buf <<  endl;
}

void dump_instr_from_mem(ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

  xed_error_enum_t xed_code = xed_decode(&new_xedd,
                                         reinterpret_cast<UINT8*>(address),
                                         max_inst_len);

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
      cerr << "invalid opcode" << endl;
      return;
  }

  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048,
                     static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;
}

void dump_entire_instr_map()
{
    for (int i=0; i < num_of_instr_map_entries; i++) {
        for (int j=0; j < translated_rtn_num; j++) {
            if (translated_rtn[j].instr_map_entry == i) {

                RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

                if (rtn == RTN_Invalid()) {
                    cerr << "Unknwon"  << ":" << endl;
                } else {
                  cerr << RTN_Name(rtn) << ":" << endl;
                }
            }
        }
        dump_instr_from_mem((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);
    }
}

void dump_instr_map_entry(int instr_map_entry)
{
    cerr << dec << instr_map_entry << " (" << instr_map[instr_map_entry].inline_count << "): ";
    cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
    cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
    cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

    ADDRINT new_targ_addr;
    if (instr_map[instr_map_entry].targ_map_entry >= 0)
        new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
    else
        new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

    cerr << " new_targ_addr: " << hex << new_targ_addr;
    cerr << "\tnew instr:";
    dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}

void dump_tc()
{
    char disasm_buf[2048];
    xed_decoded_inst_t new_xedd;
    ADDRINT address;
    unsigned int size = 0;

    address = (ADDRINT)&tc[0];

    while (address < (ADDRINT)&tc[tc_cursor])
    {
        address += size;

        xed_decoded_inst_zero_set_mode(&new_xedd, &dstate);

        xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8 *>(address), max_inst_len);

        BOOL xed_ok = (xed_code == XED_ERROR_NONE);
        if (!xed_ok)
        {
            cerr << "invalid opcode" << endl;
            return;
        }

        xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

        cerr << "0x" << hex << address << ": " << disasm_buf << endl;

        size = xed_decoded_inst_get_length(&new_xedd);
    }
}

/* ===================================================================== */
/*Call functions*/
/* ===================================================================== */

VOID count_rtn_ins(uint32_t* counter, uint32_t amount)
{
    (*counter) += amount;
}

VOID count_branch(ADDRINT branch_addr, bool is_taken)
{
    branches[branch_addr].count_seen++;
    branches[branch_addr].count_taken += is_taken ? 1 : 0;
}

VOID count_rtn_call(ADDRINT addr)
{
    rtn_call_counts[addr]++;
}

VOID count_call(ADDRINT target_addr, ADDRINT src_addr)
{
    caller_count[target_addr][src_addr]++;
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID* v)
{
    BBL bbl = TRACE_BblHead(trace);
    INS ins_tail = BBL_InsTail(bbl);
    ADDRINT ins_tail_addr = INS_Address(ins_tail);
    RTN curr_rtn = TRACE_Rtn(trace);
    ADDRINT target_addr;
    IMG img;

    if (!RTN_Valid(curr_rtn))
    {
        return;
    }

    string rtn_name = RTN_Name(curr_rtn);
    ADDRINT curr_rtn_addr = RTN_Address(curr_rtn);

    for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        ins_tail = BBL_InsTail(bbl);
        ins_tail_addr = INS_Address(ins_tail);
        curr_rtn = RTN_FindByAddress(ins_tail_addr);

        img = IMG_FindByAddress(ins_tail_addr);
        if (!IMG_IsMainExecutable(img))
        {
            continue;
        }
        else if (main_image_addr == 0)
        {
            main_image_addr = IMG_EntryAddress(img);
        }

        // Add the instruction count in the BBL to the routine ins count.
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)count_rtn_ins,
                       IARG_FAST_ANALYSIS_CALL,
                       IARG_PTR, &rtn_ins_counts[curr_rtn_addr],
                       IARG_UINT32, BBL_NumIns(bbl), IARG_END);

        if (!RTN_Valid(curr_rtn))
        {
            continue;
        }

        if (INS_IsBranch(ins_tail))
        {
            if (INS_IsDirectBranch(ins_tail))
            {
                target_addr = INS_DirectControlFlowTargetAddress(ins_tail);

                branches[ins_tail_addr].rtn_addr = RTN_Address(curr_rtn);
                branches[ins_tail_addr].rtn_name = rtn_name;
                branches[ins_tail_addr].target_addr = target_addr;

                INS_InsertCall(ins_tail, IPOINT_BEFORE, (AFUNPTR)count_branch,
                               IARG_ADDRINT, ins_tail_addr,
                               IARG_BRANCH_TAKEN, IARG_END);
            }
        }

        if (INS_IsDirectCall(ins_tail)) {
            // Get the target address of the call
            target_addr = INS_DirectControlFlowTargetAddress(ins_tail);
            caller_count[target_addr][ins_tail_addr] = 0;

            INS_InsertCall(ins_tail, IPOINT_BEFORE, (AFUNPTR)count_call,
                           IARG_ADDRINT, target_addr,
                           IARG_ADDRINT, ins_tail_addr,
                           IARG_END);
        }
    }
}

VOID instrument_routine(RTN rtn, VOID* v)
{
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)count_rtn_call,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_END);
    RTN_Close(rtn);
}

/* ===================================================================== */
/* Function Inlining                                                     */
/* ===================================================================== */

/**
 * Load all callee-caller pair with valid callers from the profiling output.
 * */
void load_inlining_candidates()
{
    ifstream csv_file(rtn_profile);

    if (!csv_file.good())
    {
        cout << "Zut. can't open " << rtn_profile << endl;
        exit(1);
    }

    if (csv_file.is_open())
    {
        string line;
        while (getline(csv_file, line))
        {
            std::vector <std::string> split_line;
            std::string split_word;
            std::istringstream string_stream(line);

            while (std::getline(string_stream, split_word, ','))
            {
                split_line.push_back(split_word);
            }

            ADDRINT callee = strtol(split_line[0].c_str(),
                                    nullptr, 16) + main_image_addr;
            ADDRINT caller = strtol(split_line[3].c_str(),
                                    nullptr, 16);

            if (caller != 0)
            {
                rtn_callers[callee] = caller + main_image_addr;
            }
        }

        csv_file.close();
    }
}

int is_valid_for_inlining(RTN rtn)
{
    int return_value = 0;
    BOOL has_ret = false;

    ADDRINT start_addr;
    INS last_ins;
    ADDRINT end_addr;

    ADDRINT target_addr;

    RTN_Open(rtn);

    start_addr = RTN_Address(rtn);

    last_ins = RTN_InsTail(rtn);
    if (!INS_IsRet(last_ins))
    {
        return_value = 1;
        goto l_cleanup;
    }

    end_addr = INS_Address(last_ins);

    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Do not inline functions that have more than one ret instructions.
        if (INS_IsRet(ins))
        {
            if (has_ret)
            {
                return_value = 2;
                goto l_cleanup;
            }

            has_ret = true;
        }

        // Do not inline functions with indirect calls/jumps.
        else if (INS_IsIndirectControlFlow(ins))
        {
            return_value = 3;
            goto l_cleanup;
        }

        // Do not inline functions that jumps outside its own scope.
        if (INS_IsBranch(ins))
        {
            target_addr = INS_DirectControlFlowTargetAddress(ins);
            if (target_addr < start_addr || target_addr > end_addr)
            {
                return_value = 4;
                goto l_cleanup;
            }
        }

        if (INS_IsSub(ins) && INS_RegWContain(ins, REG::REG_RSP))
        {
            return_value = 6;
            goto l_cleanup;
        }

        // Do not inline functions with invalid r[sb]p offsets.
        for (UINT32 memOpIndex = 0; memOpIndex < INS_MemoryOperandCount(ins); ++memOpIndex)
        {
            if (INS_MemoryOperandIsRead(ins, memOpIndex) ||
                INS_MemoryOperandIsWritten(ins, memOpIndex))
            {
                REG base_reg = INS_OperandMemoryBaseReg(ins, memOpIndex);
                ADDRDELTA displacement = INS_OperandMemoryDisplacement(ins, memOpIndex);

                if ((base_reg == REG_RSP && displacement < 0) ||
                    (base_reg == REG_RBP && displacement > 0))
                {
                    return_value = 5;
                    goto l_cleanup;
                }
            }
        }
    }

l_cleanup:
    RTN_Close(rtn);
    return return_value;
}

int find_inlining_candidates()
{
    int return_value = -1;
    RTN callee;

    for (const auto &pair : rtn_callers)
    {
        callee = RTN_FindByAddress(pair.first);

        if (!RTN_Valid(callee))
        {
            if (knob_debug)
            {
                cout << "Zut. Received invalid routine to inline." << endl;
            }
            continue;
        }

        return_value = is_valid_for_inlining(callee);
        if (return_value != 0)
        {
            if (knob_debug)
            {
                cout << "Zut. Routine can't be inlined (" << return_value << ")." << endl;
            }
            continue;
        }

        inlining_candidates[pair.first] = pair.second;
        return_value = 0;

        if (knob_debug)
        {
            cout << "Yay! " << hex << pair.first << " " << pair.second << " valid" << endl;
        }
    }

    return return_value;
}

/* ============================================================= */
/* Code Reordering                                               */
/* ============================================================= */

/**
 * Load hot loops from the code based on profiling.
 * */
void load_reordering_candidates()
{
    ifstream csv_file(branch_profile);

    if (!csv_file.good())
    {
        cout << "Zut. can't open " << branch_profile << endl;
        exit(1);
    }

    if (csv_file.is_open())
    {
        string line;
        while (getline(csv_file, line))
        {
            std::vector <std::string> split_line;
            std::string split_word;
            std::istringstream string_stream(line);

            while (std::getline(string_stream, split_word, ','))
            {
                split_line.push_back(split_word);
            }

            float count_seen = strtof(split_line[1].c_str(),
                                      nullptr);
            float count_taken = strtof(split_line[2].c_str(),
                                       nullptr);

            ADDRINT branch_addr = strtol(split_line[0].c_str(),
                                         nullptr, 16) + main_image_addr;
            float percent_taken = count_taken / count_seen;

            if (percent_taken > 1)
            {
                if (knob_debug)
                {
                    cout << "Zut. Bad count." << endl;
                }
                continue;
            }

            branch_heat[branch_addr] = percent_taken;
        }

        csv_file.close();
    }
}

/**
 * @brief Find target addresses for code reordering.
 * @return 0 for success; Other values for failure.
 */
int find_reordering_targets()
{
    int return_value = -1;
    RTN target_routine;

    for (const auto &pair : branch_heat)
    {
        target_routine = RTN_FindByAddress(pair.first);

        if (!RTN_Valid(target_routine))
        {
            if (knob_debug)
            {
                cout << "Zut. Invalid branch " << std::hex << pair.first << endl;
            }
            continue;
        }

        if (pair.second < HOT_BRANCH_THRESH)
        {
            continue;
        }

        reordering_targets[pair.first] = RTN_Address(target_routine);
        return_value = 0;
    }

    return return_value;
}

/**
 * @brief Reorder the branch instruction at `ins_addr` (described by `xedd`) such that
 *      the T/NT paths are reversed. Add a new oncond jmp to ensure correctness.
 * @param xedd     IN   Branch to invert.
 * @param ins_addr IN   Address of isntruction to invert.
 * @param new_jmp  OUT  XED object of new jmp instruction.
 * @return 0 for success; Other values otherwise.
 */
int reorder_branch(
    xed_decoded_inst_t * xedd,
    ADDRINT ins_addr,
    xed_decoded_inst_t * new_jump
)
{
    char buf[2048];

    if (KnobVerbose)
    {
        xed_format_context(XED_SYNTAX_INTEL, xedd, buf, 2048, ins_addr, 0, 0);
        cerr << "orig instr: " << hex << ins_addr << " " << buf << endl;
    }

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(xedd);

    if (category_enum != XED_CATEGORY_COND_BR)
    {
        return -1;
    }

    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(xedd);

    if (iclass_enum == XED_ICLASS_JRCXZ)
    {
        return 0; // do not revert JRCXZ
    }

    xed_iclass_enum_t inverted_class;

    switch (iclass_enum) {
        case XED_ICLASS_JB:
            inverted_class = XED_ICLASS_JNB;
            break;
        case XED_ICLASS_JBE:
            inverted_class = XED_ICLASS_JNBE;
            break;
        case XED_ICLASS_JL:
            inverted_class = XED_ICLASS_JNL;
            break;
        case XED_ICLASS_JLE:
            inverted_class = XED_ICLASS_JNLE;
            break;
        case XED_ICLASS_JNB:
            inverted_class = XED_ICLASS_JB;
            break;
        case XED_ICLASS_JNBE:
            inverted_class = XED_ICLASS_JBE;
            break;
        case XED_ICLASS_JNL:
            inverted_class = XED_ICLASS_JL;
            break;
        case XED_ICLASS_JNLE:
            inverted_class = XED_ICLASS_JLE;
            break;
        case XED_ICLASS_JNO:
            inverted_class = XED_ICLASS_JO;
            break;
        case XED_ICLASS_JNP:
            inverted_class = XED_ICLASS_JP;
            break;
        case XED_ICLASS_JNS:
            inverted_class = XED_ICLASS_JS;
            break;
        case XED_ICLASS_JNZ:
            inverted_class = XED_ICLASS_JZ;
            break;
        case XED_ICLASS_JO:
            inverted_class = XED_ICLASS_JNO;
            break;
        case XED_ICLASS_JP:
            inverted_class = XED_ICLASS_JNP;
            break;
        case XED_ICLASS_JS:
            inverted_class = XED_ICLASS_JNS;
            break;
        case XED_ICLASS_JZ:
            inverted_class = XED_ICLASS_JNZ;
            break;
        default:
            // Return error if jump is not recognized.
            return -1;
    }

    xed_int32_t disp = xed_decoded_inst_get_branch_displacement(xedd);

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(xedd);
    xed_encoder_request_set_iclass(xedd, inverted_class);
    xed_encoder_request_set_branch_displacement(xedd,
        /*xed_int32_t*/  	0,
        /*xed_uint_t*/  	1);
    // set the inverted opcode.

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode(xedd, enc_buf, max_size, &new_size);
    if (xed_error != XED_ERROR_NONE)
    {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        return -1;
    }

    xed_decoded_inst_zero_set_mode(xedd, &dstate);
    xed_error_enum_t xed_code = xed_decode(xedd, enc_buf, XED_MAX_INSTRUCTION_BYTES);
    if (xed_code != XED_ERROR_NONE)
    {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
        return -1;
    }

    if (KnobVerbose)
    {
        xed_format_context(XED_SYNTAX_INTEL, xedd, buf, 2048, ins_addr, 0, 0);
        cerr << "inverted cond jump: " << hex << ins_addr << " " << buf << endl;
    }

    // Create new jmp instruction to keep correctness of code.
    xed_uint8_t enc_buf2[XED_MAX_INSTRUCTION_BYTES];
    xed_encoder_instruction_t enc_instr;

    xed_inst1(&enc_instr, dstate,
              XED_ICLASS_JMP, 64,
              xed_relbr(disp - 3, 32));
//              xed_relbr(disp - new_size, 32));
    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req,
                                                           &enc_instr);
    if (!convert_ok)
    {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }

    xed_error = xed_encode(&enc_req, enc_buf2, max_size, &new_size);
    if (xed_error != XED_ERROR_NONE)
    {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    xed_decoded_inst_t new_xedd;
    xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

    xed_code = xed_decode(&new_xedd, enc_buf2, XED_MAX_INSTRUCTION_BYTES);
    if (xed_code != XED_ERROR_NONE)
    {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
        return -1;
    }

    if (KnobVerbose)
    {
        xed_format_context(XED_SYNTAX_INTEL, &new_xedd, buf, 2048, ins_addr, 0, 0);
        cerr << "newly added uncond jump: " << hex << ins_addr << " " << buf << endl << endl;
    }

//    xed_decoded_inst_zero_set_mode(&xedd,&dstate);
    memcpy(new_jump, &new_xedd, sizeof(xed_decoded_inst_t));
    return 0;
}

/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */

int add_new_instr_entry(
    xed_decoded_inst_t * xedd,
    ADDRINT pc,
    unsigned int size,
    UINT64 inline_count,
    bool inserted_inst)
{
    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

    if (xed_decoded_inst_get_length(xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);

    xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
      orig_targ_addr = pc + xed_decoded_inst_get_length(xedd) + disp;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(xedd);

    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode(
        xedd,
        (xed_uint8_t *)(instr_map[num_of_instr_map_entries].encoded_ins),
        max_inst_len , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    // add a new entry in the instr_map:

    instr_map[num_of_instr_map_entries].orig_ins_addr = inserted_inst ? 0 : pc;
    instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);
    instr_map[num_of_instr_map_entries].inline_count = inline_count;

    num_of_instr_map_entries++;

    // update expected size of tc:
    tc_cursor += new_size;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }

    // debug print new encoded instr:
    if (KnobVerbose) {
        cerr << "\tnew instr:";
        dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins,
                            instr_map[num_of_instr_map_entries-1].new_ins_addr);
    }

    return new_size;
}

/**
 * Find and chain the instruction to which the instruction indicated by
 * `src_entry_index` jumps.
 * */
int find_target_entry(int src_entry_index)
{
    int return_value = -1;

    // dump_instr_map_entry(src_entry_index);

    for (int i = 0; i < num_of_instr_map_entries; ++i)
    {
        instr_map_t * src_entry = &instr_map[src_entry_index];
        instr_map_t * target_entry = &instr_map[i];

        if ((src_entry->orig_targ_addr == target_entry->orig_ins_addr) &&
            (src_entry->inline_count == target_entry->inline_count))
        {
            return_value = 0;

            // dump_instr_map_entry(i);

            if (src_entry->hasNewTargAddr)
            {
                if (knob_debug)
                {
                    cout << "Zut. One source multiple targets." << endl;
                }
                continue;
            }

            src_entry->hasNewTargAddr = true;
            src_entry->targ_map_entry = i;
        }
    }

    return return_value;
}

int chain_all_direct_br_and_call_target_entries()
{
    int return_value = 0;

    for (int i=0; i < num_of_instr_map_entries; i++) {

        if (instr_map[i].orig_targ_addr == 0)
            continue;

        if (instr_map[i].hasNewTargAddr)
            continue;

        find_target_entry(i);
        return_value = find_target_entry(i);
        if (return_value != 0 && knob_debug)
        {
            cout << "Zut. Source w/o target." << endl;
        }
    }

    return 0;
}

int fix_rip_displacement(int instr_map_entry)
{
    //debug print:
    //dump_instr_map_entry(instr_map_entry);

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    //cerr << "Memory Operands" << endl;
    bool isRipBase = false;
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    xed_int64_t disp = 0;
    for(unsigned int i=0; i < memops ; i++)   {

        base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
        disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }

    }

    if (!isRipBase)
        return 0;


    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length(&xedd);

    // modify rip displacement. use direct addressing mode:
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
    xed_encoder_request_set_base0(&xedd, XED_REG_INVALID);

    //Set the memory displacement using a bit length
    xed_encoder_request_set_memory_displacement(&xedd, new_disp, new_disp_byts);

    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(&xedd);

    xed_error_enum_t xed_error = xed_encode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}

int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: Invalid direct jump from translated code to original code in routine: "
              << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // check for cases of direct jumps/calls back to the orginal target address:
    if (instr_map[instr_map_entry].targ_map_entry >= 0) {
        cerr << "ERROR: Invalid jump or call instruction" << endl;
        return -1;
    }

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;


    xed_encoder_instruction_t  enc_instr;

    ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
                       instr_map[instr_map_entry].new_ins_addr -
                       xed_decoded_inst_get_length(&xedd);

    if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

    if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_JMP, 64,
            xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));


    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }


    xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // handle the case where the original instr size is different from new encoded instr:
    if (olen != xed_decoded_inst_get_length(&xedd)) {

        new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
                   instr_map[instr_map_entry].new_ins_addr - olen;

        if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

        if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate,
            XED_ICLASS_JMP, 64,
            xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));


        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
        xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
        if (!convert_ok) {
            cerr << "conversion to encode request failed" << endl;
            return -1;
        }

        xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
        if (xed_error != XED_ERROR_NONE) {
            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
            dump_instr_map_entry(instr_map_entry);
            return -1;
        }
    }


    // debug prints:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    instr_map[instr_map_entry].hasNewTargAddr = true;
    return olen;
}

int fix_direct_br_call_displacement(int instr_map_entry)
{
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_int32_t  new_disp = 0;
    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;

    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

    if (category_enum != XED_CATEGORY_CALL &&
        category_enum != XED_CATEGORY_COND_BR &&
        category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: unrecognized branch displacement" << endl;
        return -1;
    }

    // fix branches/calls to original targ addresses:
    if (instr_map[instr_map_entry].targ_map_entry < 0) {
       int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
       return rc;
    }

    ADDRINT new_targ_addr;
    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

    xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

    // the max displacement size of loop instructions is 1 byte:
    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
    if (iclass_enum == XED_ICLASS_LOOP ||
        iclass_enum == XED_ICLASS_LOOPE ||
        iclass_enum == XED_ICLASS_LOOPNE) {
      new_disp_byts = 1;
    }

    // the max displacement size of jecxz instructions is ???:
    xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum(&xedd);
    if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
      new_disp_byts = 1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(&xedd);

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement(&xedd, new_disp, new_disp_byts);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;

    xed_error_enum_t xed_error = xed_encode(&xedd, enc_buf, max_size , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        char buf[2048];
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
        return -1;
    }

    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement(&xedd, new_disp, new_disp_byts);

    xed_error = xed_encode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    //debug print of new instruction in tc:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}

int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;

    do {
        size_diff = 0;

        if (KnobVerbose) {
            cerr << "starting a pass of fixing instructions displacements: " << endl;
        }

        for (int i=0; i < num_of_instr_map_entries; i++) {

            instr_map[i].new_ins_addr += size_diff;

            int new_size = 0;

            // fix rip displacement:
            new_size = fix_rip_displacement(i);
            if (new_size < 0)
                return -1;

            if (new_size > 0) { // this was a rip-based instruction which was fixed.

                if (instr_map[i].size != (unsigned int)new_size) {
                   size_diff += new_size - instr_map[i].size;
                   instr_map[i].size = (unsigned int)new_size;
                }

                continue;
            }

            // check if it is a direct branch or a direct call instr:
            if (instr_map[i].orig_targ_addr == 0) {
                continue;  // not a direct branch or a direct call instr.
            }


            // fix instr displacement:
            new_size = fix_direct_br_call_displacement(i);
            if (new_size < 0)
                return -1;

            if (instr_map[i].size != (unsigned int)new_size) {
               size_diff += (new_size - instr_map[i].size);
               instr_map[i].size = (unsigned int)new_size;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

   return 0;
}

int copy_instrs_to_tc()
{
    int cursor = 0;

    for (int i=0; i < num_of_instr_map_entries; i++) {
        if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
            cerr << "ERROR: Non-matching instruction addresses: " << hex
                 << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr
                 << endl;
            return -1;
        }

        memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);
        cursor += instr_map[i].size;
    }

    // tc_cursor = cursor;

    return 0;
}

inline void commit_translated_routines()
{
    // Commit the translated functions:
    // Go over the candidate functions and replace the original ones by their new successfully translated ones:

    for (int i=0; i < translated_rtn_num; i++) {

        //replace function by new function in tc

        if (translated_rtn[i].instr_map_entry >= 0) {

            if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES)
            {

                RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

                //debug print:
                if (rtn == RTN_Invalid()) {
                    cerr << "committing rtN: Unknown";
                } else {
                    cerr << "committing rtN: " << RTN_Name(rtn);
                }
                cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;


                if (RTN_IsSafeForProbedReplacement(rtn)) {

                    AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);

                    if (origFptr == NULL) {
                        cerr << "RTN_ReplaceProbed failed.";
                    } else {
                        cerr << "RTN_ReplaceProbed succeeded. ";
                    }
                    cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
                            << " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

                    dump_instr_from_mem((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
                }
            }
        }
    }
}

int allocate_and_init_memory(IMG img)
{
    // Calculate size of executable sections and allocate required memory:
    //
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
            lowest_sec_addr = SEC_Address(sec);

        if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
            highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

        // need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

            if (rtn == RTN_Invalid())
                continue;

            max_ins_count += RTN_NumIns(rtn);
            max_rtn_count++;
        }
    }

    max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.

    // Allocate memory for the instr map needed to fix all branch targets in translated routines:
    instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
    if (instr_map == NULL) {
        perror("calloc");
        return -1;
    }


    // Allocate memory for the array of candidate routines containing inlineable function calls:
    // Need to estimate size of inlined routines.. ???
    translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
    if (translated_rtn == NULL) {
        perror("calloc");
        return -1;
    }


    // get a page size in the system:
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
      return -1;
    }

    ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

    // Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:
    char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if ((ADDRINT) addr == 0xffffffffffffffff) {
        cerr << "failed to allocate tc" << endl;
        return -1;
    }

    tc = (char *)addr;
    return 0;
}

/* ===================================================================== */
/* Main translation routine                                              */
/* ===================================================================== */

/**
 * @brief Get the target address for the jump in the instructiin described in the
 *      given xed instruction.
 * @param IN    xedd Instruction to parse.
 * @param OUT   target_addr Address `xedd` jumps to.
 * @return 0 for success; Other values for failure.
 */
int get_inst_target(
    xed_decoded_inst_t * xedd,
    ADDRINT ins_addr,
    ADDRINT * target_addr)
{
    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
    xed_int32_t disp;

    if (disp_byts <= 0) {
        if (knob_debug)
        {
            cout << "Zut. call with no offset." << endl;
        }
        return -1;
    }

    disp = xed_decoded_inst_get_branch_displacement(xedd);
    *target_addr = ins_addr + xed_decoded_inst_get_length(xedd) + disp;
    return 0;
}

/**
 * Add the given `rtn` to the inst_map array, instruction by instruction. If any
 * call in rtn is to an inline target, add those instructions as if they were
 * part of `rtn`(i.e. inline this call).
 *
 * @param rtn IN    Routine to instrument.
 * */
int add_rtn_to_inst_map(RTN rtn)
{
    int rc = 0;
    bool skip;
    int size;
    INS head;
    ADDRINT rtn_addr;
    ADDRINT rtn_end;
    ADDRINT ins_addr;
    xed_decoded_inst_t xedd;
    xed_error_enum_t xed_code;
    ADDRINT target_addr;

    // Get routine boundaries.
    RTN_Open(rtn);
    head = RTN_InsHead(rtn);
    rtn_end = INS_Address(RTN_InsTail(rtn));
    RTN_Close(rtn);

    rtn_addr = RTN_Address(rtn);
    if (rtn_inline_count.count(rtn_addr) == 0)
    {
        rtn_inline_count[rtn_addr] = 0;
    }

    ins_addr = INS_Address(head);

    while (ins_addr <= rtn_end)
    {
        // debug print of routine name:
        if (KnobVerbose)
        {
            cerr << "\trtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num;
            cerr << " : " << hex << rtn_addr;
            cerr << " : " << hex << RTN_Address(rtn);
            cerr << " : " << rtn_inline_count[rtn_addr];
            cerr << "; " << hex << ins_addr << endl;
        }

        xed_decoded_inst_zero_set_mode(&xedd, &dstate);

        xed_code = xed_decode(&xedd,
                              reinterpret_cast<UINT8 *>(ins_addr),
                              max_inst_len);
        if (xed_code != XED_ERROR_NONE)
        {
            cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
            translated_rtn[translated_rtn_num].instr_map_entry = -1;
            break;
        }

        size = xed_decoded_inst_get_length(&xedd);

        //debug print of orig instruction:
        if (KnobVerbose)
        {
            cerr << "old instr: ";
            // cerr << "0x" << hex << ins_addr << ": " << INS_Disassemble(ins) << endl;
            dump_instr_from_xedd(&xedd, ins_addr);
            //xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address(ins)), INS_Size(ins));
        }

        skip = false;

        xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

        if (XED_CATEGORY_COND_BR == category_enum)
        {
            rc = get_inst_target(&xedd, ins_addr, &target_addr);
            if (rc != 0)
            {
                return -1;
            }

            xed_decoded_inst_t new_xedd;
            int new_size;

            if (reordering_targets.count(target_addr) > 0)
            {
                rc = reorder_branch(&xedd, ins_addr, &new_xedd);
                if (rc != 0)
                {
                    if (knob_debug)
                    {
                        cout << "Zut. Failed to reorder at " << std::hex << ins_addr << endl;
                    }
                    return -1;
                }

                // Add inverted jump to instr map.
                rc = add_new_instr_entry(&xedd, ins_addr, size,
                                         rtn_inline_count[rtn_addr],
                                         false);
                if (rc < 0)
                {
                    cerr << "ERROR: failed during instruction translation." << endl;
                    translated_rtn[translated_rtn_num].instr_map_entry = -1;
                    return -1;
                }

                // Add new jump to instr map.
                new_size = xed_decoded_inst_get_length(&new_xedd);
                rc = add_new_instr_entry(&new_xedd, ins_addr, new_size,
                                         rtn_inline_count[rtn_addr],
                                         true);
                if (rc < 0)
                {
                    cerr << "ERROR: failed during instruction translation." << endl;
                    translated_rtn[translated_rtn_num].instr_map_entry = -1;
                    return -1;
                }

                skip = true;
            }
        }
        else if (XED_CATEGORY_CALL == category_enum)
        {
            rc = get_inst_target(&xedd, ins_addr, &target_addr);
            if (rc != 0)
            {
                return -1;
            }

            if ((inlining_candidates.count(target_addr) > 0) &&
                (ins_addr == inlining_candidates[target_addr]))
            {
                if (knob_debug)
                {
                    cout << "Found candidate " << hex << target_addr <<
                         " -> " << ins_addr << endl;
                }
                rc = add_rtn_to_inst_map(RTN_FindByAddress(target_addr));
                if (rc != 0)
                {
                    if (knob_debug)
                    {
                        cout << "Zut. failed to inline." << endl;
                    }
                    return -1;
                }
                else if (knob_debug)
                {
                    cout << "Yay! Succeeded inline! " << num_of_instr_map_entries << endl;
                }

                rtn_inline_count[target_addr]++;

                // Ignore `ret` inst by decrementing entry count & tc cursor.
                num_of_instr_map_entries--;
                tc_cursor--;

                skip = true;
            }
        }

        if (!skip)
        {
            // Add instr into instr map:
            rc = add_new_instr_entry(&xedd, ins_addr, size,
                                     rtn_inline_count[rtn_addr], false);
            if (rc < 0)
            {
                cerr << "ERROR: failed during instruction translation." << endl;
                translated_rtn[translated_rtn_num].instr_map_entry = -1;
                return -1;
            }
        }

        ins_addr += size;
    }

    return 0;
}

void add_rtn_for_translation(RTN rtn)
{
    int rc;
    int tc_saved;
    int current_entry_count;

    // Backup translation data in case of translation failure.
    tc_saved = tc_cursor;
    current_entry_count = num_of_instr_map_entries;
    ADDRINT rtn_address = RTN_Address(rtn);

    // Skip over routines that were already added for translation.
    for (int i = 0; i < translated_rtn_num; ++i)
    {
        if (translated_rtn[i].rtn_addr == rtn_address)
        {
            return;
        }
    }

    translated_rtn[translated_rtn_num].rtn_addr = rtn_address;
    translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
    translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;

    rc = add_rtn_to_inst_map(rtn);
    if (rc != 0)
    {
        skipped_routines.insert(rtn_address);
        if (knob_debug)
        {
            cout << "Zut. Failed to add routine " << std::hex << RTN_Address(rtn)
                 << " " << RTN_Name(rtn) << " " << rc << endl;
        }
        // Backup after failure to translate, as if the routine was never translated.
        tc_cursor = tc_saved;
        num_of_instr_map_entries = current_entry_count;
        return;
    }

    translated_rtn_num++;
}

int find_candidate_rtns_for_translation(IMG img)
{
    int rc;

    RTN target;

    // Find candidates for reordering.
    load_reordering_candidates();
    rc = find_reordering_targets();
    if (rc != 0 && knob_debug)
    {
        cout << "Zut. No target was chosen for reordering." << endl;
    }

    // Find candidates for inlining.
    load_inlining_candidates();
    rc = find_inlining_candidates();
    if (rc != 0 && knob_debug)
    {
        cout << "Zut. No routine was chosen for inlining." << endl;
    }

    // Go over all chosen routines and translate them.

    for (const auto &pair : inlining_candidates)
    {
        if (skipped_routines.count(pair.second) > 0)
        {
            continue;
        }

        target = RTN_FindByAddress(pair.second);

        if (!RTN_Valid(target))
        {
            cerr << "Warning: invalid routine " << RTN_Name(target) << endl;
            continue;
        }

        add_rtn_for_translation(target);
    }

    for (auto &pair : reordering_targets)
    {
        target = RTN_FindByAddress(pair.second);

        if (skipped_routines.count(RTN_Address(target)) > 0)
        {
            continue;
        }

        if (!RTN_Valid(target))
        {
            cerr << "Warning: invalid routine " << RTN_Name(target) << endl;
            continue;
        }

        add_rtn_for_translation(target);
    }

    return 0;
}

VOID ImageLoad(IMG img, VOID * v)
{
    int rc = 0;

    // Only translate for main image.
    if (!IMG_IsMainExecutable(img))
    {
        return;
    }

    main_image_addr = IMG_EntryAddress(img);

    // step 1: Check size of executable sections and allocate required memory:
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;

    // Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0)
        return;

    cout << "after identifying candidate routines" << endl;

    // Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    rc = chain_all_direct_br_and_call_target_entries();
    if (rc < 0 )
        return;

    cout << "after calculate direct br targets" << endl;

    // Step 4: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0 )
        return;

    cout << "after fix instructions displacements" << endl;


    // Step 5: write translated routines to new tc:
    rc = copy_instrs_to_tc();
    if (rc < 0 )
        return;

    cout << "after write all new instructions to memory tc" << endl;

    if (KnobDumpTranslatedCode) {
       cerr << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

       cerr << endl << "instructions map dump:" << endl;
       dump_entire_instr_map();     // dump all translated instructions in map_instr
   }

    // Step 6: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
      commit_translated_routines();
      cout << "after commit translated routines" << endl;
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v)
{
    ADDRINT rtn_address;

    ofstream to(branch_profile);
    if (!to)
    {
        cerr << "ERROR, can't open file: " << branch_profile << endl;
        return;
    }

    for (auto &it : branches)
    {
        rtn_address = it.second.rtn_addr;

        if (it.second.count_seen > 0 && it.second.count_taken > 0)
        {
            to << "0x" << std::hex << it.first - main_image_addr
               << ", " << std::dec << it.second.count_seen
               << ", " << it.second.count_taken
               << ", " << std::dec << (float)it.second.count_taken / (float)it.second.count_seen
               << ", " << it.second.rtn_name
               << ", " << "0x" << std::hex << (rtn_address - main_image_addr)
               << endl;
        }
    }
    to.close();

    ofstream to2(rtn_profile);
    if (!to2)
    {
        cerr << "ERROR, can't open file: " << rtn_profile << endl;
        return;
    }

    ADDRINT max_caller = 0;
    UINT64 max_calls = 0;

    for (auto &pair : caller_count)
    {
        max_caller = 0;
        max_calls = 0;

        for (auto &iter : pair.second)
        {
            UINT64 current_count = iter.second;

            if ((current_count < HOT_CALL_MIN_COUNT) ||
                ((float)current_count / (float)rtn_call_counts[pair.first] < HOT_CALL_THRESH))
            {
                continue;
            }

            if (max_calls < current_count)
            {
                max_caller = iter.first - main_image_addr;
                max_calls = current_count;
            }
        }

        if (max_calls > 0)
        {
            rtn_address = pair.first;

            to2 << "0x" << std::hex << (rtn_address - main_image_addr)
                << ", " << std::dec << rtn_ins_counts[rtn_address]
                << ", " << std::dec << rtn_call_counts[rtn_address]
                << ", " << "0x" << std::hex << max_caller
                << ", " << std::dec << max_calls
                << endl;
        }
    }

    to2.close();

}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    if (prof_mode)
    {
        cout << "----- prof mode -----" << endl;
        PIN_InitSymbols();
        TRACE_AddInstrumentFunction(Trace, 0);
        RTN_AddInstrumentFunction(instrument_routine, 0);
        PIN_AddFiniFunction(Fini, 0);

        // Never returns
        PIN_StartProgram();
    }
    if (opt_mode)
    {
        cout << "----- opt mode -----" << endl;
        IMG_AddInstrumentFunction(ImageLoad, 0);

        // Never returns.
        PIN_StartProgramProbed();
    }
    else
    {
        return Usage();
    }

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
