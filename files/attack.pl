#!/usr/bin/perl 
#@esfelurm
use WWW::Mechanize;
use LWP::Simple;
use URI::URL;
use LWP::UserAgent;
use Getopt::Long;
use Parallel::ForkManager;
use HTTP::Request::Common;
use Term::ANSIColor;
use HTTP::Request::Common qw(GET);
use Getopt::Long;
use HTTP::Request;
use LWP::UserAgent;
use Digest::MD5 qw(md5 md5_hex);
use MIME::Base64;
use IO::Select;
use HTTP::Cookies;
use HTTP::Response;
use Term::ANSIColor;
use HTTP::Request::Common qw(POST);
use URI::URL;
use DBI;
use IO::Socket;
use IO::Socket::INET;
$ag = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$ag->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:0.9.3) Gecko/20010801");
$ag->timeout(10);
system('cls');

our($list,$thread); 
sub randomagent {
my @array = ('Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0',
'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31'
);
my $random = $array[rand @array];
return($random);
}
GetOptions(
    'url|u=s' => \$list,
    'threads|t=i'	=> \$thread,
) || &flag();
 
if(!defined($list) || !defined($thread)){
	&flag();
        exit;
}

my $ua = LWP::UserAgent->new;
$ua->timeout(20);

system("MEGATRONE666");
if ($^O =~ /MSWin32/) {system("cls"); }else { system("clear"); }
print color('bold green');

$ok="Result";
    if (-e $ok) 
    {
    }
    else
    {
        mkdir $ok or die "Error creating directory: $ok";
    }




print color('bold blue');
print q(
                          .:==+***++=-.                        
                :#@@@+.  -%@@@@@@@@@@@@@%*=:                   
               *@@*#@=    =@@.   ..::-=*#%@@@*-                
             .#@+::.@%    +@#  .=====--:.  .:=*#+:             
           .=*=:*@* #@-   %@-   *@@@@@@@@@@%#*=-...            
              +@#*@#-@%  =@%   =@@+:...::-=+*#@@@@*=.          
           .=%*.  .@*@@:.@@- -%@#.              .-=+##+:       
         :=+-      =@%@+#@*+@@*+#%#+-                  ::      
               -**+-@@@@@@@@%#@@@@@@@@#:                       
              ::+@@@@@@@@@@@@@@@@@@@@@@@%-                     
                +@@@[Spider Black]@@@@@@@%           
              -*#@@@@@@@@@@@@@@@@@@@@@@%=                      
          .     ::.:@@@%@@#@%#*%@@@@%*-                        
         .-*#=     *%%@=+@%.+@@*=-:                 .-==:      
            .+@+. =@=@@. %@+  +@@+           .:-+*%@%+:        
           .-.:#@@@==@*  :@@.  .%@%*+++**#%@@@@%#+-.           
            .*#--%= %@.   #@+   #@@@@@@%%#*=-: .--.            
              =@%=.-@#    =@%   ...     .:=+*%%+:              
               .%@@@@-    +@@*++++**#%@@@@@#+:                 
                 -***=.  =#@@@@@@@@@@@%*+-                     
                             .:::::.          
        @_@ Channel Telegram :  @Esfelurm #_#
                                                      
);

print color('reset');
print "                       ";
print colored ("[ FAST CMS CHECKER]",'red on_white'); 
print "                           ";

$a = 0;
open (THETARGET, "<$list") || die "[-] Can't open the file";
@TARGETS = <THETARGET>;
close THETARGET;
$link=$#TARGETS + 1;


print color("bold green"), "[*-*] START!!! ";
print color('reset');
my $pm = new Parallel::ForkManager($thread);
OUTER: foreach $site(@TARGETS){
my $pid = $pm->start and next;
chomp($site);
if($site !~ /http:\/\//) { $site = "$site/"; };
$a++;
cms();
    $pm->finish;
}
$pm->wait_all_children();
sub cms(){
$ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$ua->agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31");
$ua->timeout (20);
my $cms = $ua->get("$site")->content;
my $cmsd = $ua->get("$site/wp-includes/js/wpdialog.js")->content;
$wpsite = $site . '/xmlrpc.php?rsd';
my $wpcms = $ua->get("$wpsite")->content;
$jsite2 = $site . '/language/en-GB/en-GB.xml';
my $jcms = $ua->get("$jsite2")->content;
my $cms1 = $ua->get("$site/js/vbcache.js")->content;
$dursite = $site . '/misc/drupal.js';
my $durcms = $ua->get("$dursite")->content;
my $laravel1 = $ua->get("$site");
my $larvael2 = $ua->get("$site/vendor/composer/installed.json")->content;

if($cms1 =~/window.vBulletin/) {
print color('bold white'),"\n[$a] $site - ";
    print color("bold green"), "Vbulletin-forum";
    print color('reset');
    open(save, '>>Result/vbulletin.txt');
    print save "$site\n";   
    close(save);

}
elsif($wpcms =~/This XML file does/) {
    print color('bold white'),"\n[$a] $site - ";
    print color("bold blue"), "WordPress"; 
    print color('reset'); 
    open(save, '>>Result/Wordpress.txt');
    print save "$site\n"; 
    close(save);
}
elsif($cmsd =~/wp.wpdialog.prototype.options.closeOnEscape/) {
    print color('bold white'),"\n[$a] $site - ";
    print color("bold blue"), "WordPress"; 
    print color('reset'); 
    open(save, '>>Result/Wordpress.txt');
    print save "$site\n"; 
    close(save);
}
elsif($durcms =~/Drupal.checkPlain/) {
    print color('bold white'),"\n[$a] $site - ";
    print color("bold yellow"), "DruPal";
    print color('reset');
    open(save, '>>Result/drupal.txt');
    print save "$site\n";   
    close(save);
}
elsif($laravel1->headers_as_string =~/_session/) {
print color('bold white'),"\n[$a] $site - ";
    print color("bold cyan"), "Laravel";
    print color('reset');
    open(save, '>>Result/laravel.txt');
    print save "$site\n";   
    close(save);
}
elsif($jcms =~/www.joomla.org/) {
print color('bold white'),"\n[$a] $site - ";
    print color("bold green"), "Joomla";
    print color('reset');
    open(save, '>>Result/joomla.txt');
    print save "$site\n";   
    close(save);
}
elsif($laravel2 =~/https:\/\/packagist.org\/downloads\//) {
print color('bold white'),"\n[$a] $site - ";
    print color("bold cyan"), "Laravel 2";
    print color('reset');
    open(save, '>>Result/laravel.txt');
    print save "$site\n";   
    close(save);
}

else{
print color('bold white'),"\n[$a] $site - ";
    print color("bold red"), "Unknown"; 
    open(save, '>>Result/Unknown.txt');
    print color('reset'); 
    print save "$site\n";   
    close(save);

}

}
sub flag {
    print color('bold green');
print q(
                           .:==+***++=-.                        
                :#@@@+.  -%@@@@@@@@@@@@@%*=:                   
               *@@*#@=    =@@.   ..::-=*#%@@@*-                
             .#@+::.@%    +@#  .=====--:.  .:=*#+:             
           .=*=:*@* #@-   %@-   *@@@@@@@@@@%#*=-...            
              +@#*@#-@%  =@%   =@@+:...::-=+*#@@@@*=.          
           .=%*.  .@*@@:.@@- -%@#.              .-=+##+:       
         :=+-      =@%@+#@*+@@*+#%#+-                  ::      
               -**+-@@@@@@@@%#@@@@@@@@#:                       
              ::+@@@@@@@@@@@@@@@@@@@@@@@%-                     
                +@@@[Spider Black]@@@@@@@%           
              -*#@@@@@@@@@@@@@@@@@@@@@@%=                      
          .     ::.:@@@%@@#@%#*%@@@@%*-                        
         .-*#=     *%%@=+@%.+@@*=-:                 .-==:      
            .+@+. =@=@@. %@+  +@@+           .:-+*%@%+:        
           .-.:#@@@==@*  :@@.  .%@%*+++**#%@@@@%#+-.           
            .*#--%= %@.   #@+   #@@@@@@%%#*=-: .--.            
              =@%=.-@#    =@%   ...     .:=+*%%+:              
               .%@@@@-    +@@*++++**#%@@@@@#+:                 
                 -***=.  =#@@@@@@@@@@@%*+-                     
                             .:::::.          
        @_@ Channel Telegram :  @Esfelurm #_#                                                                                                                                                                        
);
print color('reset');
print colored ("[FAST CMS CHECKER]",'red on_white'),"\n";  
print colored ("[X]: install : cpan Parallel::ForkManager + move to Parallel-ForkManager directory + do this (perl Makefile.PL && make test && make install) or (perl Makefile.PL && dmake test && dmake install) ",'red on_white',"\n"); 
    print "\nUASGE: perl script.pl -u list.txt -t 5 \n\n";

}
