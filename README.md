# Shellcode-Prepper
A simple python script to obsucate or encrypt shellcode, in preperation for later use.

## Capabilities

Currently, RC4 and AES encryption is available for .bin files. 

## Setup
```bash
##Create virtual environment
┌──(root㉿c2)-[~/helper-scripts/Shellcode-Prepper]
└─# python3 -m venv .venv

┌──(root㉿c2)-[~/helper-scripts/Shellcode-Prepper]
└─# source .venv/bin/activate

## Install pycryptodome
┌──(.venv)─(root㉿c2)-[~/helper-scripts/Shellcode-Prepper]
└─# pip3 install -r requirements.txt
Collecting pycryptodome (from -r requirements.txt (line 1))
  Downloading pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Downloading pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 87.8 MB/s  0:00:00
Installing collected packages: pycryptodome
Successfully installed pycryptodome-3.23.0

## Run
┌──(.venv)─(root㉿c2)-[~/helper-scripts/Shellcode-Prepper]
└─# python3 payload_prepper.py
usage: payload_prepper.py [-h] -f FILE --alg ALG [--key] [--iv] [--outfile OUTFILE]
payload_prepper.py: error: the following arguments are required: -f/--file, --alg
```
