# WingFuzz
WingFuzz is a collaborative fuzzing mechanism of blackbox lead flight and greybox wingmate.

Lead flight uses Boofuzz (the successor of Sulley), Spike and Peach to perform blackbox fuzzing of network protocols.
Wingmate uses AFLNet to enchance the efficiency and effectiveness of blackbox fuzzing.

## Pre-requisite
WingFuzz and our experiments are tested under the OS of Ubuntu 20.04, either VMWare or Parallel Desktop.

- AFLNet

We have provided a `afl-fuzz` binary of linux_x86_64 under the aflnet directory. If you use other OS_archs, you can compile on your own.
```bash
git clone https://github.com/aflnet/aflnet.git
```

- Boofuzz

Boofuzz can be installed into your Python Env with the following command.
```bash
pip3 install boofuzz
```

- Spike

Spike is a C-based fuzzer creation kit, but it also includes a simple scripting capability.
There are a few command line tools which can act as interpreters to simple text files (.spk files) containing Spike primitives.
```bash
git clone https://github.com/SofianeHamlaoui/Spike-Fuzzer.git
```
Spike-Fuzzer is a build of Spike on Archlinux and we use it to develop WingFuzz.
It is worth mention that we should copy the file named `libdlrpc.so` under `/Spike-Fuzzer/usr/lib/` to `/usr/local/lib/` or `/lib/`.

- Peach

We utilize MozPeach (a fork of Peach v2.7) as it's easier to integrate. MozPeach is committed to deliver Peach as an open source product with Python compatibility and new features.
```bash
git clone https://github.com/MozillaSecurity/peach.git
```
It may work on Python3, but we have not tested.

## Boofuzz


## Spike


## Peach
Peach is a renowned fuzzing framework. *Peach Tech* that developed Peach was acquired by GitLab in 2020 to enhance its DevSecOps capability.