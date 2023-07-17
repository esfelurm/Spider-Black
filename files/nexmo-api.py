import os, vonage
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'
white = "\033[97m"
def screen_clear():
    try:_ = os.system('cls')
    except:os.system('clear')

screen_clear()
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
     {lgn}   @_@ {white}Channel Telelgnam : {lrd} @Esfelurm #_#\n{yw}-------------------------------------------------------------------------------------------------'''
    """)
link = input(f"\n{lrd}[{lgn}+{lrd}] {lgn}Input Your Nexmo List : {cn}")
with open(link) as fp:
    for star in fp:
        try:
            check = star.rstrip()
            ch = check.split('\n')[0].split('|')
            Key = ch[0]
            Sec = ch[1]
            client = vonage.Client(key=Key, secret=Sec)
            result = client.get_balance()
            print(f"{yw} {Key}|{Sec} {lgn} Working API!{pe} Balance : {result['value']:0.2f} EUR{res}")
            open("Result/Valid_Api.txt", "a").write(f"{Key}|{Sec} Balance: {result['value']:0.2f} EUR\n")
        except:
            print(f"{yw} {Key}|{Sec}  {lrd}DEAD API!{res}\n")
            pass