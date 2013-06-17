#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
#export PATH
#########################################################
#             Debian Setup & Manager v0.0.1             #
#     A few codes are taken from LNMP and LowEndBox     #
#                                                       #
#########################################################
# Absolute path this script is in. /home/user/bin
source $(dirname $(readlink -f ${BASH_SOURCE[0]}))/inc/initial_setup.sh
source $(dirname $(readlink -f ${BASH_SOURCE[0]}))/inc/functions.sh
source $(dirname $(readlink -f ${BASH_SOURCE[0]}))/inc/add_site.sh

### Check if user is root
if [ $(id -u) != "0" ]; then
    echo -e "Error: You must be root to run this script, please use root to install this script"
    exit 0
fi
### Check if server is Debian
if [ ! -f /etc/debian_version ]; then
  echo -e "Error: You do not have Debian installed."
	exit 0
fi
clear

cecho "==========================================================================" $boldcyan
cecho "          NGINX - PHP - MYSQL AUTO INSTALLER v0.0.1 FOR DEBIAN 6          " $boldgreen
cecho "==========================================================================" $boldcyan
cecho "                 Tool to perform an initial setup of a VPS                " $green
cecho "                                    and                                   " $green
cecho "                 Manange your NGINX, PHP, and mySQL Setup                 " $green
cecho "==========================================================================" $boldcyan

####################################
################Menu################
####################################
showMenu () {
	cecho "--------------------------------------------------------" $boldyellow
	cecho "                     Menu Selection                     " $boldgreen
	cecho "--------------------------------------------------------" $boldyellow
        cecho "1) Initial Setup" $boldwhite
        cecho "2) Add Additional Nginx Site" $boldwhite
        cecho "3) Create iptable Firewall Rules" $boldwhite
        cecho "4) Install mail" $boldwhite
        cecho "5) Quit" $boldwhite
}

while [ 1 ]
do
        showMenu
        read CHOICE
        case "$CHOICE" in
                "1")
initial_setup
                        ;;
                "2")
add_nginx_site
                        ;;
                "3")
add_iptables_rules
                        ;;
                 "4")
install_exim4
                         ;;
                 "5") 
                       exit
                        ;;
        esac
done

####################################
#######Server Setup & Manager#######
####################################
### Clear dpkg database to speed it up
dpkg --clear-avail


exit
