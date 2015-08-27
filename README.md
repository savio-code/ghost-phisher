<b>DISCLAIMER</b>: This program is created to be used in testing and discovering flaws in ones own network with the aim of fixing the flaws detected, <b>DO NOT</b> use the program on networks for which you dont have permission.
<hr/> 


<h4>Create portable static executables from dynamic executables that will run on every version of linux, <a target="_blank" href="http://www.elfex-pro.com">Click here</a> for more information</h4>
<hr>

<i><b>Ghost Phisher</b></i> is a Wireless and Ethernet security auditing and attack software program written using the <a href="http://www.python.org/">Python Programming Language</a> and the <a href="http://www.riverbankcomputing.co.uk/software/pyqt/intro">Python Qt GUI library</a>, the program is able to emulate access points and deploy various internal networking servers for networking, penetration testing and phishing attacks.

###Downloads
<hr/>
<a href="https://github.com/savio-code/downloads/raw/master/Ghost-Phisher_1.6_all.deb">Click here</a> to download the latest version

<br>
###Operating System Supported
<hr/>
The Software runs on any <i>Linux machine</i> with the programs <a href="#prerequisites">prerequisites</a>, But the program has been tested on the following Linux based operating systems:
<p>1. <a href="http://www.ubuntu.com/">Ubuntu KDE/GNOME</a></p>
<p>2. <a href="http://www.backtrack-linux.org/">BackTrack Linux</a></p>
<p>3. <a href="http://www.backbox.org/">BackBox Linux</a></p>

###Prerequisites
The Program requires the following to run properly:<br>
The following dependencies can be installed using the <i>Debian package installer</i> command on Debian based systems using "apt-get install program" or otherwise downloaded
and installed manually
<p>1. <a href="http://www.aircrack-ng.org/">Aircrack-NG</a></li>
<p>2. <a href="http://www.secdev.org/projects/scapy/">Python-Scapy</a></li>
<p>3. <a href="http://www.riverbankcomputing.co.uk/software/pyqt/intro">Python Qt4</a></li>
<p>4. <a href="http://www.python.org/">Python</a></li>
<p>5. <a href="http://subversion.tigris.org/">Subversion</a></li>
<p>6. <a href="http://invisible-island.net/xterm/">Xterm</a></li>
<p>7. <a href="http://www.metasploit.com/">Metasploit Framework</a> <i>(Optional)</i></li>
<hr>

###Features
<hr>
<i>Ghost Phisher</i> currently supports the following features:

<p>1. <i>HTTP Server</i></li>
<p>2. <i>Inbuilt RFC 1035 DNS Server</i></li>
<p>3. <i>Inbuilt RFC 2131 DHCP Server</i></li>
<p>4. <i>Webpage Hosting and Credential Logger (Phishing)</i></li>
<p>5. <i>Wifi Access point Emulator</i></li>
<p>6. <i>Session Hijacking (Passive and Ethernet Modes)</i></li>
<p>7. <i>ARP Cache Poisoning (MITM and DOS Attacks)</i></li>
<p>8. <i>Penetration using Metasploit Bindings</i></li>
<p>9. <i>Automatic credential logging using SQlite Database</i></li>
<p>10. <i>Update Support</i></li>

<hr>

##Installation
Installation on Debian Package supported systems:
<br><hr>
<code>root@host:~# dpkg -i ghost-phisher_1.5_all.deb</code>
<hr><br>

The <i>source code</i> for the program can be fetched using the following command on terminal
<br><hr>
<code>root@host:~# svn checkout http://github.com/savio-code/ghost-phisher/trunk/Ghost-Phisher/</code>
<hr>

###Upgrading and Updating
<hr>
<img src="http://savio-project-images.googlecode.com/files/update2.PNG" align="middle">
<br><br>
The Program automatically checks for updates each time the program is ran, if the program finds an update, it notifies
user with the message dialog box with an upgrade button, in other to update, all you simply have to do is click on the upgrade button
When the button is clicked, allow to download update files until it displays the message <b><font color="red" size="2pt">Please Restart Application</font></b>.
<hr>

###Screenshots:</h3>
<hr>
<i><b>Penetration</b></i>
<br>

<img src="http://savio-project-images.googlecode.com/files/metasploit_binding.PNG">

<br>
<i><b>ARP Cache Poisoning</b></i>
<br>

<img src="http://savio-project-images.googlecode.com/files/arp_poisoning.PNG">

<hr>


###Other Projects:

https://github.com/savio-code/fern-wifi-cracker

https://github.com/savio-code/hexorbase
