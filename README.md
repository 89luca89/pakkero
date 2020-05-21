# Pakker0

<img src="pics/logo.jpg" data-canonical-src="pics/logo.jpg" width="250" height="250" />


Credit: [alegrey91](https://github.com/alegrey91) for the logo! Thanks!

[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](http://perso.crans.org/besson/LICENSE.html)


## Introduction

**Pakker0** is a binary paker written in Go made for fun and educational purpose.

PakkerO is divided in two main pieces, the packer part (PakkerO itself) and the
launcher part.

## Install


If you have a [Go](https://golang.org/) environment ready to go, it's as easy as:

```bash
go get github.com/89luca89/pakkero
```

Once you retrieved you are ready to build:

```bash
go build github.com/89luca89/pakkero
```

The following are hard dependencies:

```
 - go -> to build the launcher
 - ls
 - sed
 - strip -> to strip the launcher
```

The following are weak dependencies

```
 - upx -> needed for launcher compression (optional)
```

**Dependencies are checked at runtime and an error message will specify what is missing**

## Part 1: the packer

PakkerO can be launched like:

```bash
pakkero --file ./target-file -o ./output-file -offset 880000 -register-dep dependency-file -c
```

![demo](pics/demo.png)


### Usage

Typing `pakker -h` the following output will be shown:

```
Usage: pakkero -file /path/to/file -offset OFFSET (-o /path/to/output) (-c) (-register-dep /path/to/file)
  -file <file>          Target file to Pack
  -o   <file>           place the output into <file> (default is <inputfile>.enc), optional
  -c                    compress the output to occupy less space (uses UPX), optional
  -offset               Offset where to start the payload (Number of Bytes)
  -register-dep         /path/to/dependency to analyze and use as fingerprint (absolutea, optional)
  -v                    Check pakkero version

```

Below there is a full explanation of provided arguments:

* **file**: The file we want to pack
* **o**: The file output that we will create
* **c**: (optional) If specificed, UPX will be used to further compress the Launcher
* **offset**: The number of bytes from where to start the payload (increases if not using compression)
* **regiser-dep** (optional) Path to a file that can be used to register the fingerprint of a dependency to ensure that the Launcher runs only if a file with similar fingerprint is present
* **v**: Print version

### Packaging

The main intent is to **not alter the payload in any way**, this can be very important
for types of binary that rely on specific order of instructions or relatively fragile timings.

#### Payload

For this purpose the payload is simply encrypted using AES256-GCM, and then compressed
using Zlib

During encryption, some basic operations are also performed on the payload:

- putting garbage random values before and after the payload to mask it
- reverse it and change each byte endianess

Encryption password is the hash SHA512 of the compiled launcher itself, thus providing
some integrity protection and anti-tampering.

#### Offset

The offset will decide **where in the output file the payload starts**.

Put simply, after the launcher is compiled (more on the launcher later), the payload is
attached to it. The offset ensures that the payload can be put anywhere after it.
All the space after the launcher until the payload is filled with random garbage.

### Obfuscation

## Part 2: the launcher


### Anti-debug

### BFD Study

### Decryption

### Execution
