#!/bin/bash

command_exists () {
	type $1 &> /dev/null
}

install_pkg () {
	if ! command_exists $1 ; then
		echo "[+] Installing $1"
		apt-get -y install $1 
		echo "[+] Install of $1 complete."
	fi
}
echo "[+] Updating system"
apt-get -y update 
apt-get -y dist-upgrade
apt-get autoremove

echo "[+] Setting up Metasploit DB"
service postgresql start
update-rc.d postgresql enable
service metasploit start
service metasploit stop

# install base packages
echo "[+] Installing base packages"
for i in gedit git gcc make libpcap-dev; do
	install_pkg $i
done

echo "[+] Need to change hostname"
echo "Enter new hostname: "
read NEW_HOSTNAME
CURRENT_HOSTNAME=$(cat /etc/hostname)
sed -i "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" /etc/hostname
sed -i "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" /etc/hosts
echo "[+] The hostname has been changed to $NEW_HOSTNAME."

echo "[+] Starting pentest tools installation. This may take a few minutes.."
# install tools through pkg management
for i in backdoor-factory masscan wpscan eyewitness sqlmap recon-ng beef-xss responder sparta mimikatz setoolkit powersploit nishang veil-evasion wifite wifiphisher goofile python-setuptools; do
	install_pkg $i
done

# install httpscreenshot
echo "[+] Installing httpscreenshot"
git clone https://github.com/breenmachine/httpscreenshot.git /opt/httpscreenshot
cd /opt/screenshot
chmod +x install-dependencies.sh && ./install-dependencies

# install smbexec
echo "[+] Installing smbexec"
git clone https://github.com/pentestgeek/smbexec.git /opt/smbexec
cd /opt/smbexec && ./install.sh

# install gitrob
echo "[+] Installing gitrob"
git clone https://github.com/michenriksen/gitrob.git /opt/gitrob
gem install bundler
service postgresql restart
echo "Enter password for postgres user: "
read -s PASSWORD
sudo -u postgres bash -c "createuser -s gitrob -P"
sudo -u postgres bash -c "createdb -O gitrob gitrob"
cd /opt/gitrob/bin
gem install gitrob

# install cmsmap
echo "[+] Installing cmsmap"
git clone https://github.com/Dionach/CMSmap.git /opt/CMSmap

# install printer exploits
echo "[+] Install printer exploits"
git clone https://github.com/MooseDojo/praedasploit /opt/praedasploit

# install discover scripts
echo "[+] Installing discover scripts"
git clone https://github.com/leebaird/discover.git /opt/discover
cd /opt/discover && ./update.sh
chmod +x /usr/share/theharvester/theHarvester.py

# install dshashes
echo "[+] Installing dshashes"
wget http://ptscripts.googlecode/svn/trunk/dshashes.py --force-direcories -O /opt/NTDSXtract/dshashes.py

# install nosqlmap
echo "[+] Installing nosqlmap"
git clone https://github.com/tcstool/NoSQLMap.git /opt/NoSQLMap
t
# install spiderfoot
echo "[+] Installing spiderfoot"
cd /opt
wget http://sourceforge.net/projects/spiderfoot/files/spiderfoot-2.7.0-src.tar.gz/download 
tar xzvf download
mv spiderfoot-2.7.0 spiderfoot
rm download
for i in lxml netaddr M2Crypto cherrypy mako PyPDF2 olefile; do
	pip install $i
done

# install windows credential editor (WDE)
echo "[+] Installing windows credential editor (WCE)"
cd /opt && mkdir wce
wget http://www.ampliasecurity.com/research/wce_v1_42beta_x64.zip
unzip wce_v1* -d /opt/wce && rm wce_v1*.zip

# install net-creds
echo "[+] Installing net-creds"
git clone https://github.com/DanMcInerney/net-creds.git /opt/net-creds

# install phishing-frenzy
echo "[+] Installing phishing-frenzy"
git clone https://github.com/pentestgeek/phishing-frenzy.git /var/www/phishing-frenzy

# install wordhound
echo "[+] Installing wordhound"
git clone https://bitbucket.org/mattinfosec/wordhound.git /opt/wordhound
cd /opt/wordhound && python setup.py install && ./setup.sh

# install tweepy
echo "[+] Installing tweepy"
git clone https://github.com/tweepy/tweepy.git /opt/tweepy
cd /opt/tweepy
python ./setup.py install

# install extras
echo "[+] Installing fuzzing lists"
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
echo "[+] Installing cheetz custom scripts"
for i in Easy-P Password_Plus_One Powershell_Popup icmpshock brutescrape reddit_xss; do
	echo "[+] Installing $i"
	git clone https://github.com/cheetz/$i.git /opt/$i
done
git clone https://github.com/macubergeek/gitlist.git /opt/gitlist

echo "[+] Completed installing tools"
