#!/usr/bin/python3

import argparse
import logging
import os
import paramiko # type: ignore
import re
import socket
import sys
from scp import SCPClient #type: ignore

class hasseled_off:

    def __init__(self, host, port, arch=None, existBusybox=None, ssh=None, busybox=None, transport=None):
        self.host = host
        self.port = int(port)

        if existBusybox != None:

            self.existBusybox = existBusybox
            self.do_not_del = True
    
        else:
            self.existBusybox = None
            self.do_not_del = False

        self.transport = ssh
        self.arch = arch

    def start(self):

        logem = "Starting up hassled_off.py"
        self.log(logem,"info")
        print(logem)

        self.inital_connection()
        
        if self.existBusybox != None:
            self.check_bb()

        elif self.arch != None:
            self.busybox_selector()
            self.upload_busybox()

        else:
            print("Dynamic busybox selection not supported at this time, please upload your own")
            quit()
            self.existBusybox = "/tmp/busybox"
            self.check_arch()
            self.busybox_selector()
            self.upload_busybox()

        logem = f"Getting Process list from {self.host}"
        self.log(logem, "info")
        print(logem)
        self.run_process_list()
        self.run_netstat()
        self.enumerate_proc()

        self.close_ssh_connection()
        logem = "Wrapping up hassled_off.py, enjoy your loot!"
        self.log(logem, "info")
        print(logem)
        quit()

    def log(self,logem, lvl):

        #set up log directory and files
        log_dir = "logs"
        log_file = "hassled_off.log"
        error_file = "error.log"

        #ensure the log directory aleady exists
        os.makedirs(log_dir, exist_ok=True)

        #create a logger object
        logger = logging.getLogger('MyLogger')
        logger.setLevel(logging.DEBUG)

        #create handlers for different levels
        info_handler = logging.FileHandler(log_file)
        info_handler.setLevel(logging.INFO)

        error_handler = logging.FileHandler(error_file)
        error_handler.setLevel(logging.ERROR)

        #defining the log format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        #set the format for the handlers
        info_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)

        #add handlers to the logger
        logger.addHandler(info_handler)
        logger.addHandler(error_handler)

        #log messages
        if lvl == "info":
            logger.info(logem)
    
        elif lvl == "error":
            logger.error(logem)

        else:
            print("The author has made a mistake and failed to set a proper logging level, please notify them to fix it")

    def transport_none(self):
        logem = f"Session to {host} is not working"
        self.log(logem, "error")
        print(logem)
        quit()

    def inital_connection(self):
        
        username = input("What is the username for the remote host?: ")
        password = input("what is the password?: ")

        try:
            #create the socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host,self.port))

            #create a paramiko transport
            self.transport = paramiko.Transport(sock)
            self.transport.connect(username=username, password=password)

            logem = f"Connected to {host}"
            self.log(logem, "info")
            print(logem)

            #make a directory for output
            os.makedirs(self.host, exist_ok=True)
    
        except Exception as e:
            logem = f"Connection error: {e}"
            self.log(logem, "error")
            print(logem)
            if self.transport:
                self.transport.close()
            if sock:
                sock.close()
            quit()

    def close_ssh_connection(self):
        if self.transport:
            self.transport.close()
        logem = "SSH connection closed"
        self.log(logem, "info")
        print(logem)

    #because mips can never be easy
    def mips_i_hate_mips(self):
        hex_command = 'which hexdump 1>/dev/null 2>/dev/null; echo $?'
        outcome = self.ssh_command(hex_command)
        if outcome == "0":

            if self.transport is None:
                self.transport_none()

            try:
                #upload and make busybox executable
                with SCPClient(self.transport) as scp:
                    scp.put('endianess/e_test.bin', '/tmp/e_test.bin')
                    scp.close()

            except Exception as e:
                logem = f"Upload of e_test.bin to {self.host} failed {e}"
                self.log(logem, "error")
                print(logem)
                self.close_ssh_connection
                quit()

            check_command = ("hexdump /tmp/e_test.bin")
            endian = self.ssh_command(check_command)
            mipsbe = '00000000 0100 0000\n0000004'
            print(mipsbe)
            if endian == "00000000 0100 0000\n0000004":
                self.arch = "mipsbe"
            elif endian == "00000000 0001 0000\n0000004":
                self.arch = "mipsel"
            else:
                logem = "Unable to tell endianess, manually check and specify with -a option"
                self.log(logem, "info")
                print(logem)
                self.close_ssh_connection()
                quit()

        else:
            logem = "Unable to tell endianess, manually check and specify with -a option"
            self.log(logem, "info")
            print(logem)
            self.close_ssh_connection
            quit()

    def ssh_command(self, command):
        if self.transport is None:
            self.transport_none()
    
        try:
            session = self.transport.open_session()
            print(command)
            session.exec_command(command)
            stdout = session.makefile('r') 
            raw_output = stdout.read().decode()
            output = raw_output.removesuffix('\n')
            print(output)
            session.close()
            return output
        
        except Exception as e:
            logem = f"Failed to execute command: {e}"
            self.log(logem, "error")
            print(logem)
            quit()

    def check_arch(self):
        command = 'uname -m'
        self.arch = self.ssh_command(command)
        
        #attempt to deal with mips, because no standaization for big or little endian
        if self.arch == "mips":
            self.arch = self.mips_i_hate_mips()
        logem = f"Remote arcitecture: {self.arch}"
        self.log(logem,"info")
        print(logem)

    #busybox selection, need to add more, current from https://www.busybox.net/downloads/binaries/1.16.1/
    def busybox_selector(self):
        bb_variants = {
            'mipsbe' : 'busybox/mips-be',
            'mipsel' : 'busybox/busybox-mipsel',
            'x86_64' : 'busybox-x86_64'
        }

        self.busybox = bb_variants.get(self.arch)

        if self.busybox == None:

            logem = f"Error architecture not found! You'll need to put up your own busybox"
            self.log(logem, "error")
            print(logem)
            self.close_ssh_connection()
            quit()
      
    def upload_busybox(self, sftp):
    
        if self.transport is None:
            self.transport_none()

        try:
            sftp = paramiko.SFTPClient.from_transport(self.transport)
        
            #upload and make busybox executable
            sftp.put(self.busybox, self.existBusybox)
            command = f"chmod 500 {self.existBusybox}"
            self.ssh_command(command)
            sftp.close
            logem = f"Uploaded {self.busybox} to {self.existBusybox}"
            self.log(logem,"info")
            print(logem)
            self.check_bb()

        except Exception as e:
            logem = f"Upload of {self.busybox} to {self.host} failed: {e}"
            self.log(logem, "error")
            print(logem)
            self.close_ssh_connection
            quit()

    def check_bb(self):

        #make sure it the busybox works
        command = f"{self.existBusybox} 1>/dev/null 2>/dev/null; echo $?"
        code = self.ssh_command(command)
        if code == "0":
            return
        else:
            logem = "The version of busybox provided does not seem compatiable with your device, sorry"
            self.log(logem, "info")
            print(logem)
            self.transport.exec_command(f"rm -f {self.existBusybox}")
            print("Removed busybox from remote host")
            self.close_ssh_connection
            quit()

    def cleanup_bb(self):

        if self.do_not_del == True:
            return
        
        else:
            command = (f"rm -f {self.existBusybox}")
            self.ssh_command(command)
            logem = f"Removed {self.existBusybox} from {self.host}"
            self.log(logem, "info")
            print(logem)

    def write_file(self, output, type):

        file_path = f"{self.host}/{type}.txt"
        bOutput = output.encode('utf-8')

        #check old file path
        if os.path.isfile(file_path):
            move_old_path = f"{self.host}/{type}_old.txt"
        
            #try to move exisiting log file
            try:
                os.rename(file_path, move_old_path)
                logem = f"Moved current file {file_path} to {move_old_path}"
                self.log(logem, "info")
                print(logem)
        
            #error and quit
            except Exception as e:
                logem = f"Error moving old {type} file {file_path} to {move_old_path} please correct before running again: {e}"
                self.log(logem, "error")
                print(logem)
                self.close_ssh_connection()
                quit()

        try:
            file = open(file_path, 'wb')
            file.write(bOutput)
            file.close()
    
        except Exception as e:
            logem = f"Error writing output to {file_path}: {e}"
            self.log(logem, "error")
            print(logem)
            self.cleanup_bb()
            self.close_ssh_connection()
            quit()
  
    def run_process_list(self):
        
        command = f"{self.existBusybox} ps -ef"
        ps_list = self.ssh_command(command)
        self.write_file(ps_list, "ps")

    def run_netstat(self):

        command = f"{self.existBusybox} netstat -tunap"
        netstat = self.ssh_command(command)
        self.write_file(netstat, "netstat")

    def enumerate_proc(self):

        command = f"{self.existBusybox} ls /proc"
        lsProc = self.ssh_command(command)
        self.write_file(lsProc, "proc")
        file_path = f"{self.host}/proc.txt"
        pid_list = []
        fd_list = []
        pid_fd_map = {}

        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                try:
                    number = int(line)
                    pid_list.append(number)
                except ValueError:
                    continue

        for pid in pid_list:

            command = f"{self.existBusybox} ls -l /proc/{pid}/fd"
            fdOut = self.ssh_command(command)
            for line in fdOut:
                line = line.strip()
                if not line:
                    continue
                else:
                    match = re.search(r'-> (.*)', line)
                    print(match)
                    if match is not None:
                        target = match.group(1)
                        if not target.startswith('/dev') and not target.startswith('socket:'):
                            fd_list.append(target)

            pid_fd_map[pid] = fd_list
        
        print(pid_fd_map)


if __name__ == "__main__":

    print(' _   _    _    ____ ____  _____ _     ____         ___  _____ _____ ')
    print('| | | |  / \  / ___/ ___|| ____| |   |  _ \       / _ \|  ___|  ___|')
    print('| |_| | / _ \ \___ \___ \|  _| | |   | | | |_____| | | | |_  | |_   ')
    print('|  _  |/ ___ \ ___) |__) | |___| |___| |_| |_____| |_| |  _| |  _|  ')
    print('|_| |_/_/   \_\____/____/|_____|_____|____/       \___/|_|   |_|    ')

    parser = argparse.ArgumentParser(prog="hassled_off.py version 0.9", description="Script to enumerate and prioritize running processes for IoT reverse engineering via ssh, written by ac0mm, Andrew Morrow for cycle 6 of CSC842", epilog="https://giphy.com/gifs/devopsreactions-SRx5tBBrTQOBi")
    parser.add_argument('-r', '--host', type=str, help='Remote host', required=True)
    parser.add_argument('-p', '--port', type=str, help='Remote host port', required=True)
    parser.add_argument('-a', '--arch', type=str, help='Specify the arch of your IoT device if know, not needed if you provided your own busybox', required=False)
    parser.add_argument('-b', '--busybox', type=str, help='Specify the location of your uploaded busybox', required=False)

    args = parser.parse_args()
    host = args.host
    port = args.port

    target = hasseled_off(host=host,port=port)

    if args.arch:
        arch = args.arch
        target = hasseled_off(host=host,port=port,arch=arch)

    if args.busybox:
        existsBusybox = args.busybox
        target = hasseled_off(host=host,port=port,existBusybox=existsBusybox)

    target.start()

