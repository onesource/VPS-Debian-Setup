### Check if user is root
if [ $(id -u) != "0" ]; then
    echo -e "Error: You must be root to run this script, please use root to install this script"
    exit 0
fi
clear

####################################
######First Time Setup Section######
####################################
### Let's update our package list

function initial_setup () {
aptitude update && aptitude safe-upgrade

read -r -p "${1:-Is this your first time running this? [Y/n]} " response
case "$response" in
    [yY][eE][sS]|[yY]) ### Execute VPS initiation if yes

## Is Sudo installed? If not, install it.
echo "Checking status of Sudo package."
dpkg --status sudo | grep -q not-installed  ## Check to see if installed
if [ $? -eq 0 ];  then						## If not install. 0 = not install
    aptitude install sudo;					## Install it
	echo -e "Sudo has been installed.\n"
else 
	echo -e "Sudo already installed.\n"
fi

### Let's create a user group call 'wheel'
echo "Checking to see if user group 'wheel' exist."
cat /etc/group | grep wheel					## Check if user group exist
if [ $? -eq 1 ];  then						## If 'wheel' does not exist
	groupadd wheel;							## Create user group 'wheel'
	echo -e "User group 'wheel' has been created.\n"
else
	echo -e "User group 'wheel' already exist.\n"
fi			  

### Create default sudo user so we don't need to use root
echo "Time to create a sudo user so we don't need to log on as root."
echo "What username do you want to use?"

### Ask for a username to create as sudo user
while read username; do						
    if id $username > /dev/null 2>&1; then	## Check if user exist. If exist ask for another username
		  echo -e "The name \033[1;31m$username\033[0m already exist. Exiting setup.\n";
		  break;
    else
		while	## Password loop
			read -s -p "Select a password." password				## Input password without showing on screen
			echo " ";
			read -s -p "Confirm password." password_confirm; do		## Retype password without showing on screen
				if [ "$password" != "$password_confirm" ]; then		## See if passwords typed are the same
					echo -e "\nPassword do not match. Please try again."
				else
					break	## If passwords are the same continue on
				fi
		done	## End Password loop
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)	## Encrypt password
		useradd -p $pass -g wheel -m $username		## Add user to 'wheel' group with password
		echo -e "\n\nUsername" $username "added to 'wheel' group"
        break			
     fi ## End Check if user exist. If exist ask for another username
done	## End while read username; do

### Add 'wheel' group to sudoer file
echo -e "Group 'wheel' added to sudoers file in /etc/sudoers\n"
echo '%wheel ALL=(ALL:ALL) ALL' >> /etc/sudoers	### Add 'wheel' group to sudoers file

### Add Dotdeb.org as source
cat /etc/apt/sources.list | grep -q -e "deb http://packages.dotdeb.org squeeze all"	## Check if dotdeb.org is in source
if [ $? -eq 0 ];  then
	echo -e "\033[1;31mSource Dotdeb.org already in /etc/apt/sources.list\033[0m"
else
	echo -e '#### 3rd Party Package ####\ndeb http://packages.dotdeb.org squeeze all\ndeb-src http://packages.dotdeb.org squeeze all' >> /etc/apt/sources.list
	echo -e "\n\033[1;32m3rd party package added: Dotdeb.org\033[0m"
	echo -e "Adding Dotdeb.org key \n"
	wget http://www.dotdeb.org/dotdeb.gpg && \
	cat dotdeb.gpg | apt-key add - && \
	rm dotdeb.gpg
	aptitude update
fi

### Functions in functions.sh file
remove_unneeded
wait_enter
install_exim4
cecho "Exim4 installed" $boldgreen
wait_enter
install_syslogd
cecho "Syslogd installed" $boldgreen
wait_enter
install_nginx_extra
cecho "Nginx installed" $boldgreen
wait_enter
aptitude -q -y install php5 php5-fpm php-pear php5-common php5-mcrypt php5-cli php5-suhosin php-apc php5-gd php5-xmlrpc php5-snmp php5-curl php5-imagick
aptitude -q -y install mysql-server mysql-client php5-mysql
php_config
cecho "PHP5 installed" $boldgreen
wait_enter
/etc/init.d/nginx start
/etc/init.d/php5-fpm start
cecho "Starting Nginx" $boldgreen
wait_enter
aptitude -q -y install fcgiwrap
cecho "Fcgiwrap installed" $boldgreen
wait_enter
secure_mysql_install   ## Secure mySQL
wait_enter
install_phpmyadmin
wait_enter
add_nginx_site          ## Add First site to Nginx
             ;;
    *)
	###Continue with rest of script
              echo "This was not your first time running this setup."
			  echo -e "No need to setup Sudo, user group 'wheel', or sudo user. \n"
              ;;
esac	### End Execute VPS initiation if yes

} #End function initial_setup
