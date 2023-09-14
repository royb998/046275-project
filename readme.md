# 046275 Project

Roy Bar-On 209161439
Ilan Mogilevski 318490828

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

To run the tool on bzip2 as required in the assignment specs, you might run the command
```
$PIN_ROOT/pin -t obj-intel64/project.so -prof -- bzip2 -k -f input.txt
$PIN_ROOT/pin -t obj-intel64/project.so -opt -- bzip2 -k -f input.txt
```
