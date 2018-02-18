#!/bin/bash -e

# == Update to 18.04 if required:
# apt update ; apt -y dist-upgrade
# apt -y install update-manager-core
# sudo do-release-upgrade -d -q

# == Then run this script
# wget https://raw.githubusercontent.com/nribault/IKEv2-setup/master/setup.sh
# chmod u+x setup.sh
# ./setup.sh

echo
echo "=== https://github.com/nribault/IKEv2-setup ==="
echo

function exit_badly {
  echo $1
  exit 1
}

[[ $(lsb_release -rs) == "18.04" ]] || exit_badly "This script is for Ubuntu 18.04 only, aborting (if you know what you are doing, delete this check)."
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"

echo "--- Configuration: VPN settings ---"
echo

echo "** Note: hostname must resolve to this machine already, to enable Let's Encrypt certificate setup **"
read -p "Hostname for VPN (e.g. vpn.example.com): " VPNHOST

apt -y install dnsutils
VPNHOSTIP=$(dig -4 +short "$VPNHOST")
[[ -n "$VPNHOSTIP" ]] || exit_badly "Cannot resolve VPN hostname, aborting"

read -p "VPN username: " VPNUSERNAME
while true; do
read -s -p "VPN password (no quotes, please): " VPNPASSWORD
echo
read -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "$VPNPASSWORD" = "$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done

echo
echo "--- Configuration: general server settings ---"
echo

read -p "Timezone (default: Europe/Paris): " TZONE
TZONE=${TZONE:-'Europe/Paris'}

read -p "Email address for sysadmin (e.g. j.bloggs@example.com): " EMAIL

SSHPORT=$(netstat -ntpl |grep -m1 sshd |awk '{print $4}' | awk -F: '{print $2}')
VPNIPPOOL="10.10.10.0/24"

echo
echo "--- Updating and installing software ---"
echo

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true update && apt-get upgrade -y

debconf-set-selections <<< "postfix postfix/mailname string ${VPNHOST}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get install -y strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-standard-plugins libcharon-extra-plugins moreutils firehol postfix mailutils unattended-upgrade certbot

ETH0ORSIMILAR=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
IP=$(ifdata -pa $ETH0ORSIMILAR)

echo
echo "Network interface: ${ETH0ORSIMILAR}"
echo "External IP: ${IP}"

if [[ "$IP" != "$VPNHOSTIP" ]]; then
  echo "Warning: $VPNHOST resolves to $VPNHOSTIP, not $IP"
  echo "Either you are behind NAT, or something is wrong (e.g. hostname points to wrong IP, CloudFlare proxying shenanigans, ...)"
  read -p "Press [Return] to continue, or Ctrl-C to abort" DUMMYVAR
fi

echo
echo "--- Configuring firehol ---"
echo

echo "version 6

server_secureShell_ports=\"tcp/$SSHPORT\"
client_secureShell_ports="default"

ipv4 masquerade any src $VPNIPPOOL dst not $VPNIPPOOL

interface any world
	protection strong

	server secureShell accept
	server isakmp accept
	server ipsecnatt accept

	client all accept

router4 ipsec src $VPNIPPOOL
	route all accept
" > /etc/firehol/firehol.conf
firehol restart

echo
echo "--- Configuring RSA certificates ---"
echo

mkdir -p /etc/letsencrypt

echo 'rsa-key-size = 4096
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 443 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 443 -j ACCEPT
renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
' > /etc/letsencrypt/cli.ini

certbot certonly --non-interactive --agree-tos --email $EMAIL --standalone -d $VPNHOST

ln -f -s /etc/letsencrypt/live/$VPNHOST/cert.pem    /etc/ipsec.d/certs/cert.pem
ln -f -s /etc/letsencrypt/live/$VPNHOST/privkey.pem /etc/ipsec.d/private/privkey.pem
ln -f -s /etc/letsencrypt/live/$VPNHOST/chain.pem   /etc/ipsec.d/cacerts/chain.pem

grep -Fq 'nribault/IKEv2-setup' /etc/apparmor.d/local/usr.lib.ipsec.charon || echo "
# https://github.com/nribault/IKEv2-setup
/etc/letsencrypt/archive/${VPNHOST}/* r,
" >> /etc/apparmor.d/local/usr.lib.ipsec.charon

aa-status --enabled && invoke-rc.d apparmor reload


echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'nribault/IKEv2-setup' /etc/sysctl.conf || echo '
# https://github.com/nribault/IKEv2-setup
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
' >> /etc/sysctl.conf

sysctl -p

# these ike and esp settings are tested on Mac 10.12, iOS 10 and Windows 10
# iOS/Mac with appropriate configuration profiles use AES_GCM_16_256/PRF_HMAC_SHA2_256/ECP_521
# Windows 10 uses AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384

echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  ike=aes256gcm16-sha256-ecp521,aes256-sha256-ecp384!
  esp=aes256gcm16-sha256!
  dpdaction=clear
  dpddelay=180s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=208.67.222.222,208.67.220.220
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"privkey.pem\"
${VPNUSERNAME} %any : EAP \""${VPNPASSWORD}"\"
" > /etc/ipsec.secrets

ipsec restart

echo
echo "--- Timezone, mail, unattended upgrades ---"
echo

timedatectl set-timezone $TZONE

sed -r \
-e "s/^myhostname =.*$/myhostname = ${VPNHOST}/" \
-e 's/^inet_interfaces =.*$/inet_interfaces = loopback-only/' \
-i.original /etc/postfix/main.cf

grep -Fq 'nribault/IKEv2-setup' /etc/aliases || echo "
# https://github.com/nribault/IKEv2-setup
root: ${EMAIL}
" >> /etc/aliases

newaliases
service postfix restart


sed -r \
-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
-e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
-i /etc/apt/apt.conf.d/50unattended-upgrades

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
' > /etc/apt/apt.conf.d/10periodic

service unattended-upgrades restart

echo
echo "--- Creating configuration files ---"
echo

cat << EOF > vpn-ios-or-mac.mobileconfig
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>LocalIdentifier</key>
        <string>${VPNHOST}</string>
        <key>OnDemandEnabled</key>
        <integer>0</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNHOST}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration (${VPNHOST})</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

cat << EOF > vpn-ubuntu-client.sh
#!/bin/bash -e
if [[ \$(id -u) -ne 0 ]]; then echo "Please run as root (e.g. sudo ./path/to/this/script)"; exit 1; fi

read -p "VPN username (same as entered on server): " VPNUSERNAME
while true; do
read -s -p "VPN password (same as entered on server): " VPNPASSWORD
echo
read -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "\$VPNPASSWORD" = "\$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done

apt-get install -y strongswan libstrongswan-standard-plugins libcharon-extra-plugins
apt-get install -y libcharon-standard-plugins || true  # 17.04+ only

ln -f -s /etc/ssl/certs/DST_Root_CA_X3.pem /etc/ipsec.d/cacerts/

grep -Fq 'nribault/IKEv2-setup' /etc/ipsec.conf || echo "
# https://github.com/nribault/IKEv2-setup
conn ikev2vpn
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        ike=aes256gcm16-sha256-ecp521!
        esp=aes256gcm16-sha256!
        leftsourceip=%config
        leftauth=eap-mschapv2
        eap_identity=\${VPNUSERNAME}
        right=${VPNHOST}
        rightauth=pubkey
        rightid=@${VPNHOST}
        rightsubnet=0.0.0.0/0
        auto=add  # or auto=start to bring up automatically
" >> /etc/ipsec.conf

grep -Fq 'nribault/IKEv2-setup' /etc/ipsec.secrets || echo "
# https://github.com/nribault/IKEv2-setup
\${VPNUSERNAME} %any : EAP \"\${VPNPASSWORD}\"
" >> /etc/ipsec.secrets

ipsec restart
sleep 5  # is there a better way?

echo "Bringing up VPN ..."
ipsec up ikev2vpn
ipsec statusall

echo
echo -n "Testing IP address ... "
VPNIP=\$(dig -4 +short ${VPNHOST})
ACTUALIP=\$(curl -s ifconfig.co)
if [[ "\$VPNIP" == "\$ACTUALIP" ]]; then echo "PASSED (IP: \${VPNIP})"; else echo "FAILED (IP: \${ACTUALIP}, VPN IP: \${VPNIP})"; fi

echo
echo "To disconnect: ipsec down ikev2vpn"
echo "To resconnect: ipsec up ikev2vpn"
echo "To connect automatically: change auto=add to auto=start in /etc/ipsec.conf"
EOF

cat << EOF > vpn-instructions.txt
== iOS and macOS ==

A configuration profile is attached as vpn-ios-or-mac.mobileconfig — simply open this to install. You will be asked for your device PIN or password, and your VPN username and password, not necessarily in that order.


== Windows ==

You will need Windows 10 Pro or above. Please run the following commands in PowerShell:

Add-VpnConnection -Name "${VPNHOST}" \`
  -ServerAddress "${VPNHOST}" \`
  -TunnelType IKEv2 \`
  -EncryptionLevel Maximum \`
  -AuthenticationMethod EAP

Set-VpnConnectionIPsecConfiguration -ConnectionName "${VPNHOST}" \`
  -AuthenticationTransformConstants GCMAES256 \`
  -CipherTransformConstants GCMAES256 \`
  -EncryptionMethod AES256 \`
  -IntegrityCheckMethod SHA256 \`
  -DHGroup ECP384 \`
  -PfsGroup ECP384 \`
  -Force


== Android ==

Download the strongSwan app from the Play Store: https://play.google.com/store/apps/details?id=org.strongswan.android

Server: ${VPNHOST}
VPN Type: IKEv2 EAP (Username/Password)
Username and password: as configured on the server
CA certificate: Select automatically


== Ubuntu ==

A bash script to set up strongSwan as a VPN client is attached as vpn-ubuntu-client.sh. You will need to chmod +x and then run the script as root.

EOF

cat vpn-instructions.txt | mail -r $USER@$VPNHOST -s "VPN configuration" -A vpn-ios-or-mac.mobileconfig -A vpn-ubuntu-client.sh $EMAIL

echo
echo "--- How to connect ---"
echo
echo "Connection instructions have been emailed to you, and can also be found in your home directory"

# necessary for IKEv2?
# Windows: https://support.microsoft.com/en-us/kb/926179
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent += AssumeUDPEncapsulationContextOnSendRule, DWORD = 2
