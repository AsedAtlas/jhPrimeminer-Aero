jhPrimeminer
============

jhPrimeminer is a optimized pool miner for primecoin.

This is Ray De Bourbon's 3.3 build, merged with deschlers linux version, 
modded by AeroCloud, ported by clintar based on porting done by tandyuk.
Instructions also by tandyuk (edited by clintar)

Requirements
Openssl and libgmp.



Build instructions:

CentOS:

yum groupinstall "Development Tools"

yum install openssl openssl-devel openssh-clients gmp gmp-devel gmp-static git

git clone https://github.com/clintar/jhPrimeminer-Aero.git

cd jhPrimeminer-Aero

make


Ubuntu:

apt-get install build-essential libssl-dev openssl git libgmp libgmp-dev

git clone https://github.com/clintar/jhPrimeminer-Aero.git

cd jhPrimeminer

make



FreeBSD 10:

(install dependencies from ports)
security/openssl
math/gmp

git clone https://github.com/clintar/jhPrimeminer-Aero.git

cd jhPrimeminer-Aero

gmake



*** Or follow this: https://bitcointalk.org/index.php?topic=359312.msg3844664

If you found this helpful PLEASE support my work.

(NOTE :These are clintar's addresses. I only ported to linux)
XPM: AGWshdugRrRBXwR63Eqs3sgdcMiZV3koJE

BTC: 1P4yWhXx7FKtWiGJYZuX5CNEm126iSFuZg
