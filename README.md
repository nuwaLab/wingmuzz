![Distinguished Paper Award](https://img.shields.io/badge/Distinguished%20Paper%20Award-%F0%9F%8F%86%20gold-gold)

**This paper has won an ACM SIGSOFT Distinguished Paper Award on ASE'25**

**Presentation YouTube Link: https://www.youtube.com/watch?v=4OiNBN5q7As**

```bibtex
@inproceedings{wingmuzz,
 author = {Zhu, Xiaogang and Dai, Enze and Feng, Xiaotao and Wang, Shaohua and Xia, Xin and Wen, Sheng and Lam, Kwok-Yan and Xiang, Yang}, 
 title = {WingMuzz: Blackbox Testing of IoT Protocols via Two-dimensional Fuzzing Schedule},
 booktitle = {Proceedings of the 40th IEEE/ACM International Conference on Automated Software Engineering},
 year = {2025},
 numpages = {13},
}
```

# WingMuzz
WingMuzz is a two-dimensional fuzzing schedule framework for IoT protocols. It enhances blackbox fuzzing with the power of greybox fuzzing (aka. *Wingmate*). 
Blackbox side uses Boofuzz (the successor of Sulley), Spike and Peach to perform blackbox fuzzing of network protocols.
Greybox side uses AFLNet to enchance the efficiency and effectiveness of blackbox fuzzing.

## 0x01 Prerequisite
WingMuzz and our experiments are tested under the OS of Ubuntu 20.04, either VMWare or Parallel Desktop.

- **AFLNet**

We have provided `afl-fuzz, afl-clang-fast, afl-clang-fast++` binary of linux_x86_64 under the aflnet directory. If you use other OS_Archs, you can apply the patch we provided and compile on your own from AFLNet's github repository.
```bash
git clone https://github.com/aflnet/aflnet.git
cd aflnet
git checkout 62d63a5
patch -p1 <~/wingmuzz/aflnet/patch/afl-fuzz.diff
```

- **Boofuzz**

```bash
pip3 install boofuzz
```

- **Spike**

Spike is a C-based fuzzer creation kit, but it also includes a simple scripting capability. There are a few command line tools which can act as interpreters to simple text files (.spk files) containing Spike primitives.
Spike-Fuzzer is a build of Spike on Archlinux and we use it to develop WingMuzz.
It is worth mention that we should copy the file named `libdlrpc.so` under `/Spike-Fuzzer/usr/lib/` to `/usr/local/lib/` or `/lib/`.
```bash
git clone https://github.com/SofianeHamlaoui/Spike-Fuzzer.git
cp ~/Spike-Fuzzer/usr/lib/libdlrpc.so /usr/local/lib/
```

- **Peach**

Peach is an open source fuzzing framework and has been developed for 20 years. There are three main versions. Peach3 is rewritten in C#, released in 2013. *Peach Tech* that developed Peach was acquired by GitLab in 2020 to enhance its DevSecOps capability. We utilize Peach v3.1.124, which is under `Peach_Fuzzing/peach`. Peach_Fuzzing repo provides some software sources of different archs, and we choose to unzip `peach-3.1.124-linux-x86_64-release.zip`.
```bash
git clone https://github.com/TideSec/Peach_Fuzzing.git
unzip peach-3.1.124-linux-x86_64-release.zip -d peach-3.1.124
```
## 0x02 Configuration

### Boofuzz

Boofuzz script configuration can be done in source code, no additional config files are required.

### Spike
Writing Spike's spk file is relatively simple, but it requires some understanding of various protocol's fields. Referring to the RFC documents of protocols, or searching for open source spk files are both feasible methods.
There are plenty of primitives of Spike, such as *s_string*, *s_string_variable*, *s_binary* and so on. We can construct spk files using these primitives.

### Peach
Peach is a renowned fuzzing framework.
Configuring Pit files is a vital part of Peach Fuzzing, whereas writing Pit files is a labor-intensive task. Hence, we provide a small tool to facilitate such task. The script is `wingmuzz/wingmuzz-scripts/blackbox/pqml2pit.py`.

First we should get a pdml file from wireshark's pcap file.
```bash
cat protocol.pcap | tshark -T pdml -i - > protocol.pqml
```
Then, we configure `pqml2pit.py` to adjust for a specific protocol, like changing PIT_FILE constant.

At last, run the script.
```bash
python3 pqml2pit.py ~/pqml/file/location.pqml
```
*NOTICE:*
- The DataModel may not necessarily completely correct, though most of it is right.
- Please make sure your mono version is not too new. Mono version <= 5.16 may work (test on v5.12).

## 0x03 Instrumentation and Run
It should be emphasized that **we don't need to instrument blackbox IoT devices in real-world scenarios.** In real-world scenarios, we only need to instrument *Wingmates* since it is required by AFLNet for greybox fuzzing. In our coverage experiments, target programs are also instrumented, but it only serves to demonstrate the effectiveness of Wingmuzz in improving coverage.

### Instrumentation

We have already provided instrumented Wingmates under the repo directory of each protocol, such as `wingmuzz/dicom/repo/*`. If you need to instrument other programs, you can use `afl-clang-fast` or `afl-clang-fast++` under the aflnet directory. For instance,

```bash
CC=~/wingmuzz/aflnet/afl-clang-fast CXX=~/wingmuzz/aflnet/afl-clang-fast++ ./configure [options...]
make
```

### Run WingMuzz

Running Wingmuzz requires two physical computers capable of communicating with each other over the same local area network (LAN). One for greybox fuzzing, click Run All for jupyter notebook `grey-main.ipynb`. Another for blackbox fuzzing,
```bash
python3 xxx-main.py
```
xxx stands for boofuzz, peach and spike.

