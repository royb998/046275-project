/*! @file
 *  This file contains an ISA-portable PIN tool for counting loop iterations
 */

#include "pin.H"
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <map>
#include <typeinfo>

using namespace std;
using std::cerr;
using std::endl;
using std::string;
using std::map;
using std::ofstream;

/* ===================================================================== */
/* Constants                                                             */
/* ===================================================================== */

const float HOT_CALL_THRESH = 0.9;

/* ===================================================================== */
/* LOOP data conatainer, */
/* ===================================================================== */

typedef struct
{
    UINT64 count_seen;
    UINT64 count_invoked;
    ADDRINT rtn_addr;
    string rtn_name;
    ADDRINT loop_target_addr;
    UINT64 curr_iter_num;
    UINT64 prev_iter_num;
    UINT64 diff_count;
} LOOP_DATA;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::map<ADDRINT, LOOP_DATA> loops;
std::map<ADDRINT, UINT64> rtn_ins_counts;
map<ADDRINT, UINT64> rtn_call_counts;
map<ADDRINT, map<ADDRINT, UINT64>> caller_count;

/* ===================================================================== */
/*Call functions*/
/* ===================================================================== */

VOID /*PIN_FAST_ANALYSIS_CALL*/ count_rtn_ins(uint32_t* counter, uint32_t amount)
{
    (*counter) += amount;
}

VOID count_branch(ADDRINT loop_addr, bool is_taken)
{
    int cur_iter = loops[loop_addr].curr_iter_num;
    int prev_iter = loops[loop_addr].prev_iter_num;

    loops[loop_addr].count_seen++;

    if (is_taken)
    {
        cur_iter++;
    }
    else
    {
        loops[loop_addr].count_invoked++;
        loops[loop_addr].diff_count += (int)(cur_iter != prev_iter);
        prev_iter = cur_iter;
        cur_iter = 0;
    }

    loops[loop_addr].curr_iter_num = cur_iter;
    loops[loop_addr].prev_iter_num = prev_iter;
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

        if (!IMG_IsMainExecutable(IMG_FindByAddress(ins_tail_addr)))
        {
            continue;
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

                if (target_addr < ins_tail_addr)
                {
                    loops[target_addr].rtn_addr = RTN_Address(curr_rtn);
                    loops[target_addr].rtn_name = rtn_name;
                    loops[target_addr].loop_target_addr = target_addr;

                    INS_InsertCall(ins_tail, IPOINT_BEFORE, (AFUNPTR)count_branch,
                                   IARG_ADDRINT, target_addr,
                                   IARG_BRANCH_TAKEN, IARG_END);
                }
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
/* Configuration                                                         */
/* ===================================================================== */


KNOB <BOOL> prof_mode(KNOB_MODE_WRITEONCE, "pintool", "prof", "0",
                      "Run in profile mode");

KNOB <BOOL> opt_mode(KNOB_MODE_WRITEONCE, "pintool", "opt", "0",
                      "Run in optimization mode");

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

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v)
{
    ofstream to("loop-count.csv");
    if (!to)
    {
        cerr << "ERROR, can't open file: loop-count.csv" << endl;
        return;
    }

    std::multimap<UINT32, LOOP_DATA> sorted_loops_map;

    for (std::map<ADDRINT, LOOP_DATA>::const_iterator it = loops.begin(); it != loops.end(); ++it)
    {
        sorted_loops_map.insert(std::pair<UINT32, LOOP_DATA>(it->second.count_seen * -1, it->second));
    }

    for (std::multimap<UINT32, LOOP_DATA>::const_iterator it = sorted_loops_map.begin(); it != sorted_loops_map.end(); ++it)
    {
        ADDRINT rtn_address = it->second.rtn_addr;

        if (it->second.count_seen > 0 && it->second.count_invoked > 0)
        {
            ADDRINT max_caller = 0;
            UINT64 max_calls = 0;
            for (auto iter = caller_count[rtn_address].begin();
                 iter != caller_count[rtn_address].end(); ++iter)
            {
                UINT64 current_count = iter->second;

                if ((float)current_count / rtn_call_counts[rtn_address] < HOT_CALL_THRESH)
                {
                    continue;
                }

                if (max_calls < current_count)
                {
                    max_caller = iter->first;
                    max_calls = current_count;
                }
            }

            to << "0x" << std::hex << it->second.loop_target_addr
               << ", " << std::dec << it->second.count_seen
               << ", " << it->second.count_invoked
               << ", " << std::dec << it->second.count_seen / (double)it->second.count_invoked
               << ", " << it->second.diff_count
               << ", " << it->second.rtn_name
               << ", " << "0x" << std::hex << rtn_address
               << ", " << std::dec << rtn_ins_counts[rtn_address]
               << ", " << std::dec << rtn_call_counts[rtn_address]
               << ", " << "0x" << std::hex << max_caller
               << ", " << std::dec << max_calls
               << endl;
        }
    }
    to.close();
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
        cout << "prof mode" << endl;
        PIN_InitSymbols();
        TRACE_AddInstrumentFunction(Trace, 0);
        RTN_AddInstrumentFunction(instrument_routine, 0);
        PIN_AddFiniFunction(Fini, 0);

        // Never returns
        PIN_StartProgram();
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
