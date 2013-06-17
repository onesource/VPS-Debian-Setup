### Check if user is root
if [ $(id -u) != "0" ]; then
    echo -e "Error: You must be root to run this script, please use root to install this script"
    exit 0
fi
clear

function wait_enter {  ## Press any key to continue function
	echo ""
	read -p "Please press enter to continue..." nothing
	}

####################################
######Script Functions Section######
####################################

# Setup Color
black='\e[30;40m'
red='\e[31;40m'
green='\e[32;40m'
yellow='\e[33;40m'
blue='\e[34;40m'
magenta='\e[35;40m'
cyan='\e[36;40m'
white='\e[37;40m'

boldblack='\e[1;30;40m'
boldred='\e[1;31;40m'
boldgreen='\e[1;32;40m'
boldyellow='\e[1;33;40m'
boldblue='\e[1;34;40m'
boldmagenta='\e[1;35;40m'
boldcyan='\e[1;36;40m'
boldwhite='\e[1;37;40m'

Reset="tput sgr0"      #  Reset color to normal without clearing screen.

cecho ()               # Echo with color. $1 = message. $2 = color.
	{
		message=$1
		color=$2
		echo -e "$color$message" ; $Reset
		return
	}

function print_info {
	cecho "$1" $boldgreen
}

function print_warn {
    cecho "$1" $boldred
}

function check_install {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        executable=$1
        shift
        while [ -n "$1" ]
        do
            DEBIAN_FRONTEND=noninteractive aptitude -q -y install "$1"
            print_info "$1 installed for $executable"
            shift
        done
    else
        print_warn "$2 already installed"
    fi
}

function check_remove {
    if [ -n "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive aptitude -q -y purge "$2"
        print_info "$2 removed"
    else
        print_warn "$2 is not installed"
    fi
}

function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd inetutils-syslogd
    invoke-rc.d inetutils-syslogd stop

    for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
    do
        [ -f "$file" ] && rm -f "$file"
    done
    for dir in fsck news
    do
        [ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
    done

    cat > /etc/syslog.conf <<END
#  /etc/syslog.conf	Configuration file for inetutils-syslogd.
#
# Include all config files in /etc/syslog.d/
#
$IncludeConfig	/etc/syslog.d/*.conf
###############
#### RULES ####
###############
# First some standard logfiles.  Log by facility.
auth,authpriv.*						/var/log/auth.log
*.*;mail.none;cron.none;auth,authpriv.none		-/var/log/messages
cron.*									-/var/log/cron.log
mail.*									-/var/log/mail.log
user.*									-/var/log/user.log
END

# cat > /etc/syslog.d/iptables.conf <<END
# ## Filter out the deny iptables drop call to a its own file
# ## "& ~" means only write to this new file without writing to the syslog (message) file
# :msg,contains,"**iptables-Hackers**: " -/var/log/iptables.log
# & ~
# END

    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/iptables.log
/var/log/user.log
/var/log/mail.log
/var/log/cron.log
/var/log/auth.log
/var/log/messages {
   rotate 4
   weekly
   missingok
   notifempty
   compress
   sharedscripts
   postrotate
      /etc/init.d/inetutils-syslogd reload >/dev/null
   endscript
}
END

    invoke-rc.d inetutils-syslogd start
}

function install_exim4 {  ## Mail Server
    check_install mail exim4
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i \
            "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
            /etc/exim4/update-exim4.conf.conf
        invoke-rc.d exim4 restart
				#dpkg-reconfigure exim4-config
    fi
}

function install_ImageMagick {
  aptitude install imagemagick
}

function remove_unneeded {
    # Some Debian have portmap installed. We don't need that.
    check_remove /sbin/portmap portmap

    # Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
    # which might make some low-end VPS inoperatable. We will do this even
    # before running apt-get update.
    check_remove /usr/sbin/rsyslogd rsyslog

    # Other packages that seem to be pretty common in standard OpenVZ
    # templates.
    check_remove /usr/sbin/apache2 'apache2*'
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd

    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        invoke-rc.d sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
}

function secure_mysql_install {
	### Change root password
	##read -s -p "Select a mySQL root password." mysqlpassword
	##mysqladmin -u root password $mysqlpassword
	mysql -uroot -p$mysqlpassword -e "[RENAME USER root TO admin_user]"	### Change root to admin_user
	mysql -uroot -p$mysqlpassword -e "[drop database test]"				### Remove test database
	cecho "\nmySQL password created" $boldgreen
	echo -e "Securing mySQL"
	mysql_secure_installation
}

function install_phpmyadmin {
  ## If "ERROR 1064 (42000) at line 72:" shows up
  ## Change "timestamp(14)" to "timestamp" in /usr/share/dbconfig-common/data/phpmyadmin/install/mysql (pma_history section).
  aptitude install phpmyadmin
}

function php_config {
  cat > /etc/php5/conf.d/apc.ini <<END
extension=apc.so
apc.enabled=1
apc.shm_size="196"
apc.ttl=3600
apc.user_ttl=3600
apc.max_file_size=1M
END
  
  
}

function add_iptables_rules {
  cecho "What is your server's SSH port?" $boldgreen
  cecho "FYI: If you enter the wrong port number you will be LOCKED OUT." $boldred
  read -p "SSH Port#? " sshport
	#read -p "Server ip address? " IP_SERVER_MAIL
  ## Flush all iptables rule
  iptables -F
  iptables -X
  iptables -t nat -F
  iptables -t nat -X
  iptables -t mangle -F
  iptables -t mangle -X
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
  ## Create the iptables firewall rules
  cat > /etc/iptables.firewall.rules <<END
*filter

#  Accept all incoming SSH
#  The -dport number should be the same port number you set in sshd_config
-A INPUT -p tcp --dport $sshport -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --sport $sshport -m state --state ESTABLISHED -j ACCEPT

# Reject all  - default deny unless explicitly allowed
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT DROP

### Allow Established connections ###
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#  Localhost access
#  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

#  Accept all incoming web traffic (HTTP) port 80 & (HTTPS) port 443
-A INPUT -p tcp -m multiport --dport 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m multiport --sport 80,443 -m state --state ESTABLISHED -j ACCEPT

# Accept localhost for mySQL and drop all other
-A INPUT -p tcp -s localhost --dport 3306 -j ACCEPT
-A INPUT -p tcp --dport 3306 -j DROP

# Allow outgoing mail to use Amazon SES
#-A INPUT -p tcp -–dport 587 -d $IP_SERVER_MAIL -m state –state NEW,ESTABLISHED -j ACCEPT
#-A OUTPUT -p tcp -s $IP_SERVER_MAIL -–sport 587 -m state –state ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp --dport 587 -j ACCEPT


#  Allow outgoing SSH
-A OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

#  Allow ping from world to server
-A INPUT -p icmp --icmp-type 8 -j ACCEPT
-A OUTPUT -p icmp --icmp-type 0 -j ACCEPT

#  Allow ping from server to world
-A OUTPUT -p icmp --icmp-type 8 -j ACCEPT
-A INPUT -p icmp --icmp-type 0 -j ACCEPT

#  Prevent DoS Attack
-A INPUT -p tcp -m multiport --dport 80,443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Allow FTP
# Purely optional, but required for WordPress to install its own plugins or update itself.
#-A INPUT -p tcp -m state --state NEW --dport 21 -j ACCEPT

# Allow Aptitude updates and install
-A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
-A OUTPUT -p tcp -d http.us.debian.org -j ACCEPT
#-A OUTPUT -p tcp -d volatile.debian.org -j ACCEPT
-A OUTPUT -p tcp -d security.debian.org -j ACCEPT
-A OUTPUT -p tcp -d packages.dotdeb.org -j ACCEPT

# Allow access to Askimet spam filter
-A OUTPUT -p tcp -d rest.akismet.com -j ACCEPT
-A OUTPUT -p tcp -d akismet.com -j ACCEPT

#  Log iptables denied calls
-N LOGGING
-A INPUT -j LOGGING
-A LOGGING -m limit --limit 5/min -j LOG --log-prefix "**iptables-Hackers**: " --log-level 7
-A LOGGING -j DROP

COMMIT
END

  iptables-restore < /etc/iptables.firewall.rules   ## Start up iptables
  cecho "iptable rules created at /etc/iptables.firewall.rules." $boldgreen

  ## Create the iptables firewall rules 
  cat > /etc/network/if-up.d/firewall <<END
#!/bin/sh
iptables-restore < /etc/iptables.firewall.rules
END
chmod +x /etc/network/if-up.d/firewall
  cecho "Setup auto restart of iptables after server reboot." $boldgreen
}

function install_nginx_extra {
	aptitude -q -y install nginx-extras		##Install Nginx-extra from dotdeb
	cat > /etc/nginx/nginx.conf <<END
# Run as the www-data user
user www-data;

# For high performance you'll need one worker process per disk spindle
# but in most cases 1 or 2 is fine.
worker_processes 4;

#error_log  /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
  # Max concurrent connections = worker_processes * worker_connections
  # You can increase this past 1024 but you must set the rlimit before starting
  # ngxinx using the ulimit command (say ulimit -n 8192)
  worker_connections 1024;
  #multi_accept on;

  # Linux performance awesomeness on
  use epoll;
}

http {
  server_names_hash_bucket_size 64;
  #types_hash_max_size 2048;
  server_tokens off;
  #keepalive_timeout 65;

  # More Linux performance awesomeness
  sendfile on;
  tcp_nopush  on;
  tcp_nodelay off;

  # Max size of a request from a client (usually a POST).  This will limit
  # the size of file uploads to your app
  client_max_body_size 10m;

  ## MIME stuff
  # Mime-type table
  include /etc/nginx/mime.types;
  # Default mime-type if nothing matches from the table
  default_type application/octet-stream;
  index index.php index.htm index.html redirect.php;

  ## Logging
  # Specify a log format compatible with Apache's combined format
  log_format main '$remote_addr - $remote_user [$time_local] '
                '"$request" $status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for"' ;
  #access_log /var/log/nginx/access.log main;
  #error_log /var/log/nginx/error.log main;

  upstream php {
  server unix:/tmp/php-fpm.sock;
  }

  ## Compression
  gzip on;
  gzip_http_version 1.1;
  gzip_comp_level 2;
  gzip_proxied any;
  gzip_min_length  1100;
  gzip_buffers 16 8k;
  gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;
  # Some version of IE 6 don't handle compression well on some mime-types, so just disable them
  gzip_disable "MSIE [1-6].(?!.*SV1)";
  # Set a vary header so downstream proxies don't send cached gzipped content to IE6
  gzip_vary on;


	##
	#FastCGI
	##
	#limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;


	##
	# nginx-naxsi config
	##
	# Uncomment it if you installed nginx-naxsi
	##

	#include /etc/nginx/naxsi_core.rules;

	##
	# nginx-passenger config
	##
	# Uncomment it if you installed nginx-passenger
	##
	
	#passenger_root /usr;
	#passenger_ruby /usr/bin/ruby;

	## Detect when HTTPS is used
	map $scheme $fastcgi_https {
		default off;
		https on;
	}
	
	##
	# Virtual Host Configs
	##
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;  #Our individual site vhost server files will live here
}
END
}

function add_nginx_site {
cecho "We will now create the folders for your site." $boldgreen
read -p "Lets use your domain name as the folder name. Ex. domain.com " yoursitename
mkdir -p /srv/www/$yoursitename /srv/www/$yoursitename/public /srv/www/$yoursitename/logs		##Create directory for Site
chown www-data:www-data /srv/www/$yoursitename/public/ -R		##Set owner of folder
touch /etc/nginx/sites-available/$yoursitename
ln -s /etc/nginx/sites-available/$yoursitename /etc/nginx/sites-enabled/$yoursitename

## Create the conf files
## Add conf file to sites-available
cat > /etc/nginx/sites-available/$yoursitename <<END
server {
#listen 80; ## listen for ipv4; this line is default and implied
#listen [::]:80 default ipv6only=on; ## listen for ipv6
 
server_name www.$yoursitename.com;
root /srv/www/$yoursitename.com/public;
access_log /srv/www/$yoursitename.com/logs/access.log;
error_log /srv/www/$yoursitename.com/logs/error.log;
client_max_body_size 8M;
client_body_buffer_size 128k;

	index index.html index.htm index.php;

	location = /favicon.ico {
		log_not_found off;
		access_log off;
	}
	
	location = /robots.txt {
		allow all;
		log_not_found off;
		access_log off;
	}
	
	# Make sure files with the following extensions do not get loaded by nginx because nginx would display the source code, and these files can contain PASSWORDS!
	location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\.php)?|xtmpl)$|^(\..*|Entries.*|Repository|Root|Tag|Template)$|\.php_ {
	deny all;
	}

	# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac).
	location ~ /\. {
		deny all;
		access_log off;
		log_not_found off;
	}

    # static file 404's aren't logged and expires header is set to maximum age
    location ~* \.(jpg|jpeg|gif|css|png|js|ico|html)$ {
    access_log off;
    expires max;
    }

#Send the php files to upstream to PHP-FPM
#This can also be added to separate file and added with an include
	# use fastcgi for all php files
		location ~ \.php$ {
	# Forbid PHP on upload dirs
		if ($uri ~ "uploads") {
			return 403;
		}
	try_files $uri =404;
		fastcgi_pass 127.0.0.1:9000;
		fastcgi_index index.php;
		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
		include fastcgi_params;
    }

###################################################
###################################################
## Wordpress permalink

#multisite start
rewrite ^(.*phpmyadmin.*)$ $1 last;	## Allow access to phpmyadmin directory
rewrite ^.*/files/(.*)$ /wp-includes/ms-files.php?file=$1 last;
	if (!-e $request_filename) {
		rewrite  ^(.+)$  /index.php?q=$1  last;
	}
#multisite end
###################################################
###################################################

## Set location of phpmyadmin
	location /phpmyadmin {
				 root /usr/share/;
				 index index.php index.html index.htm;
				 location ~ ^/phpmyadmin/(.+\.php)$ {
								 try_files $uri =404;
								 root /usr/share/;
								 fastcgi_pass 127.0.0.1:9000;
								 fastcgi_index index.php;
								 fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
								 include /etc/nginx/fastcgi_params;
				 }
				 location ~* ^/phpmyadmin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
								 root /usr/share/;
				 }
	}
	location /phpMyAdmin {
				 rewrite ^/* /phpmyadmin last;
	}		

 
    # deny access to apache .htaccess files
    location ~ /\.ht
    {
        deny all;
    }

} ## Close server directive
END

## Create the initial index.php for site
touch /srv/www/$yoursitename/public/index.php
cat > /srv/www/$yoursitename/public/index.php <<END
<!doctype html>
<html>
<head>
	<title>Welcome to $yoursitename</title>
</head>
<body>
	<br /><center><h1>Feel the power of NginX, Baby!!!</h1></center>
</body>
<html>
END

/etc/init.d/mysql restart
/etc/init.d/php5-fpm restart
/etc/init.d/nginx restart
}
