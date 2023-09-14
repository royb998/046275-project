# 046275 Project

Roy Bar-On 209161439
Ilan Mogilevski 318490828

## Using the tool

### Building

You can build the tool using the command

```make obj-intel64/project.so```

Where the current directory is the `src` directory included in the assignment submission.

### Running

Initially the target program must be profiled using the following command:

```$PIN_ROOT/pin -t obj-intel64/project.so -prof -- <target>```
Where `target` is the command line (binary and arguments) for the program for the tool to inspect.

This should result in two output files: `rtn-count.csv` and `branch-count.csv`.

For the optimized run itself, run the tool using the following target:

```$PIN_ROOT/pin -t obj-intel64/project.so -opt -- <target>```

#### Example

To run the tool on bzip2 as required in the assignment specs, you might run the  following commands:
```
$PIN_ROOT/pin -t obj-intel64/project.so -prof -- bzip2 -k -f input.txt
$PIN_ROOT/pin -t obj-intel64/project.so -opt -- bzip2 -k -f input.txt
```

## Overview

### Choosing candidates

For routine inlining we have chosen a single inlining location for each routine, based on the most
dominant call to that function, exceeding 80% of the calls to that routine. We have ignored for
inlining routines that are only called once.

For code reordering we have chosen any conditional branch which is taken (that is, jumps) more than
60% of the times it's seen.

In both cases we only optimize code in the main image.

### Profiling outputs

After profiling the target binary, we get two resulting csv files, `rtn-count.csv` (used for
routine inlining) and `branch-count.csv` (used for code reordering).

The fields of `rtn-count.csv` are (in order):
    - Offset of the routine (relative to the image's entry point)
    - dynamic instruction count of the routine
    - call count of the routine
    - the offset of the most common caller of the routine (relative to the image's entry point)
    - and the amount of calls from the most common caller.

The fields of `branch-count.csv` are (in order):
    - Offset of the branch instruction (relative to the image's entry point).
    - The amount of times the branch was seen (taken or otherwise).
    - The amount of times the branch was taken.
    - The fraction (%) of times the branch was taken out of the times it was seen.
    - The name of the routine the branch instruction is in.
    - The offset (relative to the image's entry point) of the routine containing
    the branch instruction.
