# Tbouncer

This is the source code of Tbouncer.

## Project Structure

This project is designed to fuzz different types of Tcons (Trusted Communication Nodes) using various fuzzing techniques. It is divided into the following directories:

### `process-based/`
This directory contains code based on **eBPF (Extended Berkeley Packet Filter)** technology. It is used to fuzz **Process-based Tcons**. The eBPF-based code interacts with the kernel to trace and monitor system calls and activities of the processes, helping to detect vulnerabilities during fuzzing.

### `vm-based/`
This directory contains code for fuzzing **VM-based Tcons**. The code is designed to fuzz virtual machine-based Tcons by interacting with the virtual machine environment and performing various tests to detect issues or vulnerabilities.

## Usage

You can build and run the fuzzing tools in each directory depending on the type of Tcon you want to fuzz.

