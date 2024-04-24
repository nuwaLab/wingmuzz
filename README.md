# WingFuzz
WingFuzz is a collaborative fuzzing mechanism of blackbox lead flight and greybox wingmate.

Lead flight uses Boofuzz (the successor of Sulley), Spike and Peach to perform blackbox fuzzing of network protocols.
Wingmate uses AFLNet to enchance the efficiency and effectiveness of blackbox fuzzing.

## Pre-requisite
WingFuzz and our experiments are tested under the OS of Ubuntu 20.04, either VMWare or Parallel Desktop.

- AFLNet

We have provided a `afl-fuzz` binary of linux_x86_64 under the aflnet directory. If you use other OS_Archs, you can compile on your own.
```bash
git clone https://github.com/aflnet/aflnet.git
```

- Boofuzz

Boofuzz can be installed into your Python Env with the following command.
```bash
pip3 install boofuzz
```

- Spike

Spike is a C-based fuzzer creation kit, but it also includes a simple scripting capability. There are a few command line tools which can act as interpreters to simple text files (.spk files) containing Spike primitives.
```bash
git clone https://github.com/SofianeHamlaoui/Spike-Fuzzer.git
```
Spike-Fuzzer is a build of Spike on Archlinux and we use it to develop WingFuzz.
It is worth mention that we should copy the file named `libdlrpc.so` under `/Spike-Fuzzer/usr/lib/` to `/usr/local/lib/` or `/lib/`.

- Peach

Peach is an open source fuzzing framework and has been developed for 20 years. There are three main versions. Peach1 and Peach2 are written in Python, released in 2004 and 2007 respectively. Peach3 is rewritten in C#, released in 2013.
```bash
git clone https://github.com/TideSec/Peach_Fuzzing.git
```
We utilize Peach v3.1.124, which is under `Peach_Fuzzing/peach`. Peach_Fuzzing repo provides some software sources of different archs, and we choose to unzip `peach-3.1.124-linux-x86_64-release.zip`.

## Boofuzz


## Spike


## Peach
Peach is a renowned fuzzing framework. *Peach Tech* that developed Peach was acquired by GitLab in 2020 to enhance its DevSecOps capability.