# WingFuzz
WingFuzz is a collaborative fuzzing mechanism of blackbox lead flight and greybox wingmate.

Lead flight uses Boofuzz (the successor of Sulley), Spike and Peach to perform blackbox fuzzing of network protocols.
Wingmate uses AFLNet to enchance the efficiency and effectiveness of blackbox fuzzing.

## Pre-requisite
WingFuzz and our experiments are tested under the env of Ubuntu 20.04, either VMWare or Parallel Desktop.

Boofuzz can be installed into your Python Env with the following command.
```bash
pip3 install boofuzz
```

Spike is a C based fuzzer creation kit, but it also includes a simple scripting capability.
There are a few command line tools which can act as interpreters to simple text files (.spk files) containing Spike primitives.
```bash
git clone https://github.com/SofianeHamlaoui/Spike-Fuzzer.git
```
Spike-Fuzzer is a build of Spike on Archlinux and we use it to develop WingFuzz.
It is worth mention that we should copy the file named `libdlrpc.so` under `/Spike-Fuzzer/usr/lib/` to `/usr/local/lib/` or `/lib/`.

## Boofuzz


## Spike


## Peach