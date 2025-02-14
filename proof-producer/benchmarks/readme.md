# Proof producer benchmarking framework

## Prerequisites

It is recommended to run benchmarks with `nix develop .#proof-producer-benchmarks` environment. Another option is to setup python virtual environment using `requirements.txt` file.

## Usage

The framework supports several execution scenarios (`-s` option). To run the default one (DFRI pipeline), use the following command:

```bash
python3 ./main.py -t /path/to/trace/file -b /path/to/proof-producer-binary [-o output_artifact_dir] # default output dir is /tmp
```

Alternatively you can run proof generation and verification for the specific circuit (for example, `-s bytecode`), or for all the supported circuits one by one: `-s single_circuits`.

For more detailed description of options, please refer to `./main.py --help`

## Benchexec support

The default mode of running proof-producer binary is simple invocation via `subprocess` module. To use features of [benchexec](https://github.com/sosy-lab/benchexec) library like measurement of CPU time, memory consumption, and isolation against other running processes, you need to perform additional setup (steps for Ubuntu 21.10 or newer):

- Install [fuse-overlayfs](https://github.com/containers/fuse-overlayfs):
```bash
sudo apt install fuse-overlayfs
```
- Add the following prefix for each benchmark run:
```bash
systemd-run --user --scope --slice=benchexec -p Delegate=yes python3 ./main.py -m benchexec <other required benchmark options>
```

For troubleshooting and setup on other systems, please refer to https://github.com/sosy-lab/benchexec/blob/main/doc/INSTALL.md

# Trace regeneration

Supported regeneration of traces for proof producer. Sample traces are stored in `traces` subdirectory. To recollect them, run:
```bash
NIL_BIN=/path/to/nil/binary/directory TRACE_NAME=./traces/hundred_plus_hundred_trace ./traces/generate_traces.sh
```
