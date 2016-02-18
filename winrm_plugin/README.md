# cloudify-winrm-plugin

preliminary requirements:

optinal
kerberos==1.1.1
sudo apt-get install python-kerberos  libkrb5-dev 

win side:

winrm set winrm/config/client/auth @{Basic="true"}

winrm set winrm/config/service/auth @{Basic="true"}

winrm set winrm/config/service @{AllowUnencrypted="true"}
