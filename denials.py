# Copyright (C) 2019 baalajimaestro
# Copyright (C) 2020-2021 Giovix92

import re
import os
import sys, getopt
import shutil

version = "v1.2"
wfixes = []
write = False
namefile = "fixes.txt"
inputfile = "denials.txt"

print("Giovix92's SELinux denial fixer,", version)

if os.path.exists("sepolicy"):
    shutil.rmtree("sepolicy")

if os.path.exists("denials.txt"):
    os.remove("denials.txt")
    
if os.path.exists("fixes.txt"):
    os.remove("fixes.txt")

for i in range(1, len(sys.argv)):
    # Verbose
    if sys.argv[i] == "-v" or sys.argv[i] == "--verbose":
        write = True
        os.makedirs("sepolicy")
        print("Verbose mode enabled!")
        print("Outputting every denial into its respective file.")
    # Logcat
    elif sys.argv[i] == "-l" or sys.argv[i] == "--logcat":
        print("Parsing denials from logcat!")
        try:
            if not "-" in sys.argv[i+1]:
    	        logname = sys.argv[i+1]
    	        print("Using custom logcat!")
            else:
                sys.exit()
        except:
    	    logname = "logcat.txt"
        if not os.path.isfile(logname):
            print("logcat is missing! Exiting.")
            sys.exit()
        os.system('cat %s | grep "avc: denied" > denials.txt' % logname)
    # Help part
    elif sys.argv[i] == "-h" or sys.argv[i] == "--help":
    	print("Usage: denials.py [-v] [-l logcat_name]")
    	sys.exit()

if not os.path.isfile(inputfile):
	print("denials file is missing! Exiting.")
	sys.exit()

with open(inputfile) as denfile:
    data = denfile.read()
data = data.split("\n")
data.remove(data[-1])

# Parsin' the data
for i in data:
    test = re.search("{",i)
    test2 = re.search("}",i)
    se_context = i[test.span()[0]:test2.span()[0]+1]
    test = re.search("scontext",i)
    scontext = i[(test.span()[0]):].split(":")[2]
    test = re.search("tcontext",i)
    tcontext = i[(test.span()[0]):].split(":")[2]
    test = re.search("tclass",i)
    tclass = i[(test.span()[0]):].split("=")[1].split(" ")[0]
    fix = f"allow {scontext} {tcontext if scontext != tcontext else 'self'}:{tclass} {se_context};\n"
    wfixes.append(fix)

wfixes = list(dict.fromkeys(wfixes))
for i in wfixes:
    tempvar = i
    tempvar = tempvar.split(" ")
    if write:
        namefile = "sepolicy/" + tempvar[1] + ".te"
    if not os.path.exists(namefile):
        os.mknod(namefile)
    with open(namefile, "a") as ffnew:
        ffnew.write(i)
