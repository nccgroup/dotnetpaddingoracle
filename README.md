dotnetpaddingoracle
===================

Small script to check if the .NET web application is vulnerable to padding Oracle
This script actually verify if the oracle is present and exploitable, not just if the patch has been installed.

usage
------
    dotnetpaddingoracle.py [-h] [-t] [-b] [-d] [-s] [-p PARAMETER] Burp request file
  
    Perform the padding Oracle attack on .NET web application
    positional arguments:
    Burp request file     Request sample from Burp
    optional arguments:
  
    -h, --help            show this help message and exit
    
    -t, --test-vuln       Test for the padding Oracle vulnerability
    
    -b, --no-burp         Disable Burp proxying
    
    -d, --decrypt         Decrypt
    
    -s, --ssl             use ssl transport
    
    -p PARAMETER, --parameter PARAMETER
    
                          Parameter to use as Oracle

Few tips
---------

 * Make sure that you use the 'ssl' flag in the relevant cases, as this could lead to false negative results.
 * The burp request file should be taken from burp with the "copy to file" function only (plain text file)
 * Generally speaking you don't need the "-p" flag as the script chooses the right parameter anyway.
 * By default the script will try to connect through burp (for debugging purposes) via 127.0.0.1:8080 (check the mtools.py script to modify the values). You can disable this with the "-b" flag.

Limitations
------------
 * The script won't probably work on Windows systems
 * You need at least Python 3.2 to make it run properly (or Python > 3.0 with the argparse module)
 * It does not do encryption (not enough time and testing data), you still need padbuster for this.
