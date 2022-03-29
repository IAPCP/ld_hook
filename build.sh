#!/bin/bash

# should be changed manually
echo "export COMPILE_COMMANDS_DB=\"/root/test.db\"" >> ~/.bashrc
echo "export PROJ_ROOT=\"/root\"" >> ~/.bashrc
cd /root; mkdir build_binutils; cd build_binutils; ../binutils-2.38/configure --prefix="/usr"; make -j$(nproc); make install

apt update; apt install apt-transport-https ca-certificates -y

cat << EOF > /etc/apt/sources.list
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free
deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free
deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free

deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free
deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free

deb https://mirrors.tuna.tsinghua.edu.cn/debian-security bullseye-security main contrib non-free
deb-src https://mirrors.tuna.tsinghua.edu.cn/debian-security bullseye-security main contrib non-free
EOF

apt update; apt upgrade -y

# old way to install ld-new
# rm /usr/bin/ld; ln -s /root/build_binutils/ld/ld-new /usr/bin/ld
