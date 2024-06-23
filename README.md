# hasseled_off

## Demo

  - Link coming soon

## Description

For DSU CSC842 - Security Tools Cycle 6

Script to enumerate remote MIPS architecture IoT device via SSH, the script collects a process list, netstat, grabs binaries based on open file descriptors for running processes, the exe associated with the pid, and any dependencies those devices have. Additionally if script extensions are provided it will search the device and collect scripts matching that syntax, parses all collected binaries and scripts for a small dictionary of words related to passwords and provides a list of files that had hits.

## Prerequisties

- python 3.8 or higher
- paramiko
- termcolor
- busybox (https://www.busybox.net/downloads/binaries/1.16.1/)

## Installation

  - git clone https://github.com/ac0mm/hasseled_off.git

## Usage

usage: hassled_off.py version 0.9 [-h] -r HOST -p PORT [-a ARCH] [-b BUSYBOX] [-x EXTENSION]

Script to enumerate and prioritize running processes for IoT reverse engineering via ssh, written by ac0mm, Andrew Morrow for cycle 6 of CSC842

options:
  -h, --help            show this help message and exit
  -r HOST, --host HOST  Remote host
  -p PORT, --port PORT  Remote host port
  -a ARCH, --arch ARCH  Specify the arch of your IoT device if know, not needed if you provided your own busybox
  -b BUSYBOX, --busybox BUSYBOX
                        Specify the location of your uploaded busybox
  -x EXTENSION, --extension EXTENSION
                        Extensions for script files you want to search for seperated by commas

https://giphy.com/gifs/devopsreactions-SRx5tBBrTQOBi

In the current version you will need to provide your own busybox (-b), there is a goal in the future to make it work dynamically but I need to identify more devices to help test this against.

## Examples

Without scripts:
python3 hassled_off.py -r 192.168.1.1 -p 22 -b /tmp/busybox

With scripts (lua and javascript in this example):

python3 hassled_off.py -r 192.168.1.1 -p 22 -b /tmp/busybox -x js,lua

## Three Main Points

- Quickly collect binaries, dependencies and related files for running processes in the process list
- Enumeration of running process and processes with network sockets associated
- Quickly search the file system for provided extensions and collect them

## Why I am Interested

As part of CSC-844 I am reverse enineering a GL-AR750S travel router for potential vulnerabilities, and knowing that I am likely to do this again in the future I elected to build a tool, hasseled_off, to help perform some initial triage of the target device that can be used to help scope on good potential places to start enumerating. The primary assumption is that processes that are running and have exposed network sockets that have vulnerabilities will be more suscptible to remote attacks, which is why the process list and nestat are pulled. A big gap right now is looking at any kernel loaded kernel modules associated with any RF communications.

# Areas of Improvement

- More architecture support, MIPSBE got the initial love since that is what I am currently testing against
- More organized features, instead of just organizing by path to location on file system a folder organized by pids with links to the downloaded files
- Report about the running process, cmdline, file descriptors, network sockets
- Parsing the command line for referenced configuration files or scripts and grabbing those
- Checking loaded kernel modules and collect those for analysis as well
