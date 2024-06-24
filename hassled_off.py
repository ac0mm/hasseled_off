#!/usr/bin/python3

import argparse
from termcolor import colored# type: ignore
import filecmp
import getpass
import hashlib
import logging
import os
import paramiko # type: ignore
import re
import socket
import subprocess

class hasseled_off:

    def __init__(self, host, port, arch=None, existBusybox=None, ssh=None, busybox=None, transport=None, password=None, user=None, extensions=None):
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
        self.local_path = []
        self.interesting_files = []

        if extensions:

            self.extensions = []
            self.extensions = extensions.split(',')

    def start(self):

        logem = "Starting up hassled_off.py"
        self.log(logem,"info")
        print(colored(logem, 'green'))

        #kicks off ssh connection
        self.inital_connection()
        
        #check if provided busybox works
        if self.existBusybox != None:
            self.check_bb()

        #todo attempts to upload a busybox if you provided the arch
        elif self.arch != None:
            print(colored("Upload not working yet, please upload your own", "red"))
            quit()
            self.busybox_selector()
            self.upload_busybox()

        #todo dynamic detection and busybox upload
        else:
            print(colored("Dynamic busybox selection not supported at this time, please upload your own", "red"))
            quit()
            self.existBusybox = "/tmp/busybox"
            self.check_arch()
            self.busybox_selector()
            self.upload_busybox()

        #get a process list and netstat
        self.run_process_list()
        self.run_netstat()

        #enumerates /proc/#/ for file descriptors and gets files
        self.enumerate_proc()

        #checks binaries downloaded from /proc for dependncies and downloads them
        self.bin_depends()

        #gets scripts if extensions were provided
        if self.extensions:
            self.get_scripts()

        #prints interesting files list
        print(colored("Files with interesting strings found: ", "blue"))
        unique_filename = []
        for file in self.interesting_files:
            file_str = str(file)
            name_index = file_str.find('name=')

            if name_index != -1:
                almostfilename = file_str[name_index + len("name="):]
                almostfilename = almostfilename.strip("'")
                scratch = []
                scratch = almostfilename.split()
                filename = scratch[0]
                filename = filename.strip("'")
                if filename not in unique_filename:
                    unique_filename.append(filename)

        for ufilename in unique_filename:             
            
            print(colored(ufilename, "white", "on_blue"))

        self.close_ssh_connection()
        logem = "Wrapping up hassled_off.py, enjoy your loot!"
        self.log(logem, "info")
        print(colored(logem, "green"))
        quit()

    #function to log info and errors
    def log(self,logem, lvl):

        #set up log directory and files
        log_dir = "logs"
        log_file = "logs/hassled_off.log"
        error_file = "logs/error.log"

        #ensure the log directory aleady exists
        os.makedirs(log_dir, exist_ok=True)

        #create a logger object
        logger = logging.getLogger('hassled_off_log')
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
            print(colored("The author has made a mistake and failed to set a proper logging level, please notify them to fix it", "red"))

    #handle if socket is lost
    def transport_none(self):
        logem = f"Session to {self.host} is not working"
        self.log(logem, "error")
        print(colored(logem, "red"))
        quit()

    #connect to remote device
    def inital_connection(self):
        
        #didn't see the need to make these arguments, only need to exist for connection
        self.username = input(colored("What is the username for the remote host?: ", "magenta"))
        self.password = getpass.getpass(colored("what is the password?: ", "magenta"))

        try:
            #create the socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host,self.port))

            #create a paramiko transport
            self.transport = paramiko.Transport(sock)
            self.transport.connect(username=self.username, password=self.password)

            logem = f"Connected to {self.host}"
            self.log(logem, "info")
            print(colored(logem, "green"))

            #make a directory for output
            os.makedirs(self.host, exist_ok=True)

        #handle connection errors    
        except Exception as e:
            logem = f"Connection error: {e}"
            self.log(logem, "error")
            print(colored(logem, "red"))
            if self.transport:
                self.transport.close()
            if sock:
                sock.close()
            quit()

    #gracefully terminate connection when called
    def close_ssh_connection(self):
        if self.transport:
            self.transport.close()
        logem = "SSH connection closed"
        self.log(logem, "info")
        print(colored(logem, "green"))

    #because mips can never be easy, currently not used
    def mips_i_hate_mips(self):
        hex_command = 'which hexdump 1>/dev/null 2>/dev/null; echo $?'
        outcome = self.ssh_command(hex_command)
        if outcome == "0":

            if self.transport is None:
                self.transport_none()

            try:
                #upload a file to attempt to test endianess of MIPS, will need to modify to use cat since scp is not a working thing
                with SCPClient(self.transport) as scp: #type: ignore
                    scp.put('endianess/e_test.bin', '/tmp/e_test.bin')
                    scp.close()

            except Exception as e:
                logem = f"Upload of e_test.bin to {self.host} failed {e}"
                self.log(logem, "error")
                print(colored(logem, "red"))
                self.close_ssh_connection
                quit()

            #not my favorite technique but isn't working well either, maybe tailing \n?
            check_command = ("hexdump /tmp/e_test.bin")
            endian = self.ssh_command(check_command)
            if endian == "00000000 0100 0000\n0000004":
                self.arch = "mipsbe"
            elif endian == "00000000 0001 0000\n0000004":
                self.arch = "mipsel"
            else:
                logem = "Unable to tell endianess, manually check and specify with -a option"
                self.log(logem, "info")
                print(colored(logem, "red"))
                self.close_ssh_connection()
                quit()

        #was to difficult, farming it back to the user
        else:
            logem = "Unable to tell endianess, manually check and specify with -a option"
            self.log(logem, "info")
            print(colored(logem, "red"))
            self.close_ssh_connection
            quit()

    #function that runs commands via paramkio then returns results in byte form
    def ssh_command(self, command):
        if self.transport is None:
            self.transport_none()
    
        try:
            session = self.transport.open_session()
            session.exec_command(command)
            stdout = session.makefile('r') 
            rawOutput = stdout.read()
            session.close()
            return rawOutput
        
        except Exception as e:
            logem = f"Failed to execute {command}: {e}"
            self.log(logem, "error")
            print(colored(logem, "red"))
            quit()

    #currently unused but part of dynamic detection of architecture for uploading busybox
    def check_arch(self):
        command = 'uname -m'
        self.arch = self.ssh_command(command)
        
        #attempt to deal with mips, because no standaization for big or little endian
        if self.arch == "mips":
            self.arch = self.mips_i_hate_mips()
        logem = f"Remote arcitecture: {self.arch}"
        self.log(logem,"info")
        print(colored(logem, "blue"))

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
            print(colored(logem, "red"))
            self.close_ssh_connection()
            quit()

    #upload busybox, needs to be fixed as sftp and scp are not great options. Will have to use cat or echo to write file out      
    def upload_busybox(self, sftp):
    
        if self.transport is None:
            self.transport_none()

        #boo boo IoT dropbear is limited in what I can use for uploads, this won't work
        try:
            sftp = paramiko.SFTPClient.from_transport(self.transport)
        
            #upload and make busybox executable
            sftp.put(self.busybox, self.existBusybox)
            command = f"chmod 500 {self.existBusybox}"
            self.ssh_command(command)
            sftp.close
            logem = f"Uploaded {self.busybox} to {self.existBusybox}"
            self.log(logem,"info")
            print(colored(logem, "green"))
            self.check_bb()

        except Exception as e:
            logem = f"Upload of {self.busybox} to {self.host} failed: {e}"
            self.log(logem, "error")
            print(colored(logem, "red"))
            self.close_ssh_connection
            quit()

    #attempts to run busybox to determine if it will work
    def check_bb(self):

        #make sure it the busybox works
        command = f"{self.existBusybox} 1>/dev/null 2>/dev/null; echo $?"
        rawCode = self.ssh_command(command)
        almostCode = rawCode.decode()
        code = almostCode.strip('\n')

        #if the exit code was zero it worked, mileage will vary on if all functions work
        if code == "0":
            return
        else:
            logem = "The version of busybox provided does not seem compatiable with your device, sorry"
            self.log(logem, "info")
            print(colored(logem, "red"))
            self.transport.exec_command(f"rm -f {self.existBusybox}")
            print(colored("Removed busybox from remote host", "green"))
            self.close_ssh_connection
            quit()

    #removes dynamically uploaded busybox
    def cleanup_bb(self):

        if self.do_not_del == True:
            return
        
        else:
            command = (f"rm -f {self.existBusybox}")
            self.ssh_command(command)
            logem = f"Removed {self.existBusybox} from {self.host}"
            self.log(logem, "info")
            print(colored(logem, "green"))

    #writes any files pulled to disk
    def write_file(self, output, type, ext, status):

        #build the filepath based on host and input, attempts to keep the full path
        file_path = f"{self.host}/{type}.{ext}"

        #logic to determine if to append or overwrite a file
        if status == "new":

            #check old file path
            if os.path.isfile(file_path):
                move_old_path = f"{self.host}/{type}_old.txt"
        
                #try to move exisiting log file
                try:
                    os.rename(file_path, move_old_path)
                    logem = f"Moved current file {file_path} to {move_old_path}"
                    self.log(logem, "info")
                    print(colored(logem, "blue"))
        
                #error and quit
                except Exception as e:
                    logem = f"Error moving old {type} file {file_path} to {move_old_path} please correct before running again: {e}"
                    self.log(logem, "error")
                    print(colored(logem, "red"))
                    self.close_ssh_connection()
                    quit()

        #write the data
        try:
            file = open(file_path, 'ab')
            file.write(output)
            file.close()
    
        except Exception as e:
            logem = f"Error writing output to {file_path}: {e}"
            self.log(logem, "error")
            print(colored(logem, "red"))
            self.cleanup_bb()
            self.close_ssh_connection()
            quit()

    #gets process list and writes to disk
    def run_process_list(self):

        logem = f"Getting process list from {self.host}"
        self.log(logem, "info")
        print(colored(logem, "green"))

        command = f"{self.existBusybox} ps -ef"
        ps_list = self.ssh_command(command)
        self.write_file(ps_list, "ps", "txt", "new")

    #gets netstat and writes to disk
    def run_netstat(self):

        logem = (f"Getting netstat from {self.host}")
        self.log(logem, "info")
        print(colored(logem, "green"))

        command = f"{self.existBusybox} netstat -tunap"
        netstat = self.ssh_command(command)
        self.write_file(netstat, "netstat", "txt", "new")

    #enumerates proc, gets unique executables from fd or exe
    def enumerate_proc(self):

        logem = (f"Enumerating /proc/<pid>/ for files")
        self.log(logem, "info")
        print(colored(logem, "green"))

        #get proc so it can be parsed for numerical pids
        command = f"{self.existBusybox} ls /proc"
        lsProc = self.ssh_command(command)
        self.write_file(lsProc, "proc", "txt", "new")
        file_path = f"{self.host}/proc.txt"

        #intalize various variables
        pid_list = []
        fd_list = []
        pid_fd_map = {}
        unique_fds = set()
        exe_list = []
        unique_exe = set()
        fileA = f"{self.host}/local_bin_hash.txt"
        fileB = f"{self.host}/remote_bin_hash.txt"
        fileC = f"{self.host}/local_fd_hash.txt"
        fileD = f"{self.host}/remote_fd_hash.txt"


        #pulls numerical pids from the ls /proc file and adds them to list
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                try:
                    number = int(line)
                    pid_list.append(number)
                except ValueError:
                    continue

        #gets file descriptors
        for pid in pid_list:

            command = f"{self.existBusybox} ls -l /proc/{pid}/fd"
            rawFdOutS = self.ssh_command(command)
            almostFdOutS = rawFdOutS.decode()
            fdOutS = almostFdOutS.strip('\n')
            fdOut = fdOutS.split('\n')
            for line in fdOut:
                line = line.strip()
                if not line:
                    continue
                else:
                    
                    #search for regex when a fd points to something
                    match = re.search(r'-> (.*)', line)
                    if match is not None:
                        target = match.group(1)
                        #strip out things that won't be files and add the remainder to a list
                        if not target.startswith('/dev') and not target.startswith('socket:') and not target.startswith('pipe:') and not target.startswith('anon_inode:') and not target.startswith('/proc'):
                            fd_list.append(target)

            #associates the list of file descriptors with the pid
            pid_fd_map[pid] = fd_list

        #makes unique list of binaries spotted in process list
        for pid, fds in pid_fd_map.items():
            for fd in fds:
                if fd not in unique_fds:
                    unique_fds.add(fd)

        for fd in unique_fds:

            logem = f"Getting {fd} from {self.host}"
            self.log(logem, "info")
            print(colored(logem, "cyan"))

            #get unique referenced file descriptors
            self.get_file(fd, "fd")

        #goes through the pid list to get a list of the executable
        for pid in pid_list:

            command = f"{self.existBusybox} ls -l /proc/{pid}/exe"
            rawExeOutS = self.ssh_command(command)
            almostExeOutS = rawExeOutS.decode()
            exeOutS = almostExeOutS.strip('\n')
            exeOut = exeOutS.split('\n')
            for line in exeOut:
                line = line.strip()
                if not line:
                    continue
                else:
                    match = re.search(r'-> (.*)', line)
                    if match is not None:
                        target = match.group(1)
                        exe_list.append(target)

        #adds unique exes
        for exe in exe_list:
            if exe not in unique_exe:
                unique_exe.add(exe)

        #grabs unique exes
        for exe in unique_exe:

            logem = f"Getting {exe} from {self.host}"
            self.log(logem, "info")
            print(colored(logem, "cyan"))

            self.get_file(exe, "bin")

        #checks that dowloaded files matched
        self.compare_files(fileA, fileB)
        self.compare_files(fileC, fileD)

    #function to download file
    def get_file(self, exe, type):

        #set the stage for saving the file on disk
        basedir = f"{self.host}"
        path = exe.lstrip('/')
        totalPath = f"{basedir}/{path}.{type}"
        directory, file_name = os.path.split(path)
        mkdir = os.path.join(basedir, directory)
        os.makedirs(mkdir, exist_ok=True)

        #hash the remote file
        hashCommand = f"{self.existBusybox} md5sum {exe}"
        rawHash = self.ssh_command(hashCommand)

        #writes the hash value to a file to compare later
        self.write_file(rawHash, f"remote_{type}_hash", "txt", "update")

        #sftp and scp suck with IoT dropbears, but cat works
        command = f"{self.existBusybox} cat {exe}"
        rawExeOut = self.ssh_command(command)

        #writes the output to disk
        self.write_file(rawExeOut, path, type, "new" )

        #gets the local hash
        self.get_local_hash(path, type)
        self.local_path.append(totalPath)

        #looks for strings of interest
        self.string_hunter(totalPath)

    #hashes local files downloaded
    def get_local_hash(self, path, type):

        md5 = hashlib.md5()
        chunk_size = 8192
        filePath = f"{self.host}/{path}.{type}"

        with open(filePath, 'rb') as file:
            while chunk := file.read(chunk_size):
                md5.update(chunk)

        md5sum = str(md5.hexdigest())
        output = f"{md5sum}  /{path}\n"
        bOutput = output.encode('utf-8')

        self.write_file(bOutput, f"local_{type}_hash", "txt", "update")

    #compare the file of the remote and local
    def compare_files(self, fileA, fileB):

        are_equal = filecmp.cmp(fileA, fileB, shallow=False)

        if are_equal:
            logem = f"No difference in {fileA} and {fileB}"
            self.log(logem, "info")
            print(colored(logem, "green"))
        else:
            logem = f"Whao hoss, there is a difference between {fileA} and {fileB}, you should check it out and manually pull the incorrect file(s)"
            self.log(logem, "info")
            print(colored(logem, "red"))

    #checks for libs and downloads them
    def bin_depends(self):     

        #intialize some vars
        fileA = f"{self.host}/local_lib_hash.txt"
        fileB = f"{self.host}/remote_lib_hash.txt"
        binFile = []
        binFiles = []
        libFiles = []
        unique_libs = []
        almostLibPath = []

        logem = f"Analyzing files pulled back from {self.host}"
        self.log(logem, "info")
        print(colored(logem, "blue"))

        #runs through list of exe's collected
        for yobin in self.local_path:

            #makes sure the are really exes
            result = subprocess.run(["file", yobin], capture_output=True, text=True)
            output = result.stdout

            value = output.split()

            #strips needed info from the file command output
            if value[1] == "ELF":
                rawbinary = value[0]
                binary = rawbinary.strip(':')
                procType = value[2]
                sigBit = value[3]
                if value[4] == "pie":
                    rawarch = value[6]
                    depends = value[12]
                else:
                    rawarch = value[5]
                    depends = value[11]
                
                arch = rawarch.strip(',')

                binFile = binary, procType, sigBit, arch, depends
           
            binFiles.append(binFile)

        logem = f"Checking for dependancies for dynamic binaries from {self.host}"
        self.log(logem, "info")
        print(colored(logem, "blue"))

        #checks if they are dynamic and adds them to a list
        for exe in binFiles:

            try:

                depends = exe[4]

            except:
                depends = "no"
                continue
            
            if depends == "dynamically":

                #calls function to look for dependncies 
                libs = self.ldd(exe)
                libFiles.append(libs)

        #builds a list of unique requirements
        for libs in libFiles:
            for lib in libs:
                if lib not in unique_libs:
                    unique_libs.append(lib)

        #finds and gets them off the remote host
        for lib in unique_libs:
            command = f"{self.existBusybox} find / -name {lib}"
            output = self.ssh_command(command)
            rawLibPaths = output.decode()
            LibPaths = rawLibPaths.strip('\n')
            almostLibPath = LibPaths.split('\n')
            libPath = almostLibPath[0]

            logem = f"Getting {libPath} from {self.host}"
            self.log(logem, "info")
            print(colored(logem, "cyan"))
            self.get_file(libPath, "lib")

        self.compare_files(fileA, fileB)            

    #function for looking for dependncies 
    def ldd(self, exe):

        scratch = []
        libs = []

        #pull needed elements from list
        arch = exe[3]
        proc = exe[0]

        #only supported arch right now
        if arch == "MIPS":

            #invokes readelf
            result = subprocess.run(["mips-linux-gnu-readelf", '-d', proc], capture_output=True, text=True)
            output = result.stdout

            #parses output, looks for dependencies and adds them to a list then r eturns them
            lines = output.split('\n')
            for line in lines:
                
                scratch = line.split()

                try: 
                    temp_val = scratch[1]

                    if temp_val == "(NEEDED)":

                        rawlib = scratch[4]
                        a = rawlib.strip('[')
                        lib = a.strip(']')
                        libs.append(lib)
                
                except:
                    continue
            
            return(libs)

    #looks for specific phrases and tags the file they were found in
    def string_hunter(self, filePath):

        prey = ['password', 'pass', 'key']

        for word in prey:

            pattern = re.compile(re.escape(word), re.IGNORECASE)

            try:
                with open(filePath, 'r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        if pattern.search(line):
                            
                            if file not in self.interesting_files:
                                self.interesting_files.append(file)
            
            except FileNotFoundError:
                logem = f"Error checking {file} due to file not found"
                self.log(logem, "error")
                print(colored(logem, "red"))
                continue

            except PermissionError:
                logem = f"Error checking {file} due to permissions"
                self.log(logem, "error")
                print(colored(logem, "red"))
                continue

    #gets scripts if extensions were provided
    def get_scripts(self):
        fileA = f"{self.host}/local_bin_hash.txt"
        fileB = f"{self.host}/remote_bin_hash.txt"

        for extension in self.extensions:

            command = f"{self.existBusybox} find / -name *.{extension} 2>/dev/null"
            output = self.ssh_command(command)
            rawScriptPaths = output.decode()
            almostScriptPaths = rawScriptPaths.strip('\n')
            scriptPaths = almostScriptPaths.split('\n')
 
            for path in scriptPaths:

                logem = f"Getting {path} from {self.host}"
                self.log(logem, "info")
                print(colored(logem, "cyan"))

                self.get_file(path, "script")

        self.compare_files(fileA, fileB)

if __name__ == "__main__":

    print(colored(' _   _    _    ____ ____  _____ _     ____         ___  _____ _____ ', "yellow"))
    print(colored('| | | |  / \  / ___/ ___|| ____| |   |  _ \       / _ \|  ___|  ___|', "yellow"))
    print(colored('| |_| | / _ \ \___ \___ \|  _| | |   | | | |_____| | | | |_  | |_   ', "yellow"))
    print(colored('|  _  |/ ___ \ ___) |__) | |___| |___| |_| |_____| |_| |  _| |  _|  ', "yellow"))
    print(colored('|_| |_/_/   \_\____/____/|_____|_____|____/       \___/|_|   |_|    ', "yellow"))

    parser = argparse.ArgumentParser(prog="hassled_off.py version 0.9", description="Script to enumerate and prioritize running processes for IoT reverse engineering via ssh, written by ac0mm, Andrew Morrow for cycle 6 of CSC842", epilog="https://giphy.com/gifs/devopsreactions-SRx5tBBrTQOBi")
    parser.add_argument('-r', '--host', type=str, help='Remote host', required=True)
    parser.add_argument('-p', '--port', type=str, help='Remote host port', required=True)
    parser.add_argument('-a', '--arch', type=str, help='Specify the arch of your IoT device if know, not needed if you provided your own busybox', required=False)
    parser.add_argument('-b', '--busybox', type=str, help='Specify the location of your uploaded busybox', required=False)
    parser.add_argument('-x', '--extension', type=str, help='Extensions for script files you want to search for seperated by commas', required=False)

    args = parser.parse_args()
    host = args.host
    port = args.port
    extensions = args.extension

    target = hasseled_off(host=host,port=port)

    if args.arch:
        arch = args.arch
        target = hasseled_off(host=host,port=port,arch=arch, extensions=extensions)

    if args.busybox:
        existsBusybox = args.busybox
        target = hasseled_off(host=host,port=port,existBusybox=existsBusybox, extensions=extensions)

    target.start()

