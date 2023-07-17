import os, time
from concurrent.futures import ThreadPoolExecutor
start_time = time.time()
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'
white = "\033[97m"
def screen_clear():_ = os.system('cls')
def v3(star):
 host,port,pwd,user = '', '','',''
 if "URL:" in star:
    star = fp.readline()
 if "METHOD:" in star:
    star = fp.readline()
 if "MAILHOST:" in star:
    star = star.replace(" ", "")
    star = star.replace('"', "")
    star = star.replace('\n', "")
    x = star.split(':', 1)
    host = x[1] + "|"
    star = fp.readline()
 if "MAILPORT:" in star:
    star = star.replace(" ", "")
    star = star.replace('"', "")
    star = star.replace('\n', "")
    x = star.split(':', 1)
    port = x[1] + "|"
    star = fp.readline()
 if "MAILUSER:" in star:
    star = star.replace(" ", "")
    star = star.replace('"', "")
    star = star.replace('\n', "")
    x = star.split(':', 1)
    user = x[1] + "|"
    star = fp.readline()
 if "MAILPASS:" in star:
    star = star.replace(" ", "")
    star = star.replace('"', "")
    star = star.replace("\n", "")
    x = star.split(':', 1)
    pwd = x[1]
    star = fp.readline()
 if "MAILFROM:" in star:star = fp.readline()
 if "FROMNAME:" in star:pass
 mrigel = open("Duplicated.txt", "a")
 mrigel.write(f'{host}{port}{user}{pwd}\n')
 mrigel.close()
 lines_seen = set()
 with open("successful.txt", "w") as output_file:
   for each_line in open("Duplicated.txt", "r"):
     if each_line not in lines_seen:
       output_file.write(each_line)
       lines_seen.add(each_line)
 output_file.close()      
screen_clear()
print (f"    {lgn}XPROAD.\n{white}Formatting your file + Remove Duplicated {pe}2in1\n{rd}channel : {lgn}https://t.me/esfelurm")
link = input(f"{lrd}[{lgn}+{lrd}] {lgn}Enter your file.txt : {cn}")
if not os.path.isfile(link):
    print(f'{lrd}[{lgn}+{lrd}] {yw}Enter a valid .txt file in the some folder')
with open(link) as fp:
  for star in fp:
    if not star:
       pass
    with ThreadPoolExecutor(max_workers=40) as executor:
        executor.map(v3, [star])
        executor.shutdown(wait=True)
print(f"--- %s seconds --- List Is {lgn}READY To {pe}CHECK {lrd}" % (time.time() - start_time))