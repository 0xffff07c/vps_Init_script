#!/bin/bash

# 设置错误处理
set -e

# 检测网络是否支持 IPv4 和 IPv6
IPV4=$(ping -c 1 8.8.8.8 > /dev/null 2>&1 && echo "yes" || echo "no")
IPV6=$(ping -c 1 2001:4860:4860::8888 > /dev/null 2>&1 && echo "yes" || echo "no")

echo "正在检测 VPS 网络..."

if [[ "$IPV4" == "no" && "$IPV6" == "no" ]]; then
    echo "该 VPS 不支持 IPv4 和 IPv6。"
else
    # 仅支持 IPv4
    if [[ "$IPV4" == "yes" && "$IPV6" == "no" ]]; then
        echo "该 VPS 仅支持 IPv4。"
    # 仅支持 IPv6
    elif [[ "$IPV4" == "no" && "$IPV6" == "yes" ]]; then
        echo "该 VPS 仅支持 IPv6。"
        read -p "建议您添加 DNS64，以方便下载 IPv4 下的资源。是否继续？（输入 y 进行添加，输入 n 跳过）： " DNS64_CHOICE
        if [[ "$DNS64_CHOICE" == "y" ]]; then
            echo "正在添加 DNS64..."
            echo -e "nameserver 2606:4700:4700::64\nnameserver 2606:4700:4700::6400" | sudo tee /etc/resolv.conf > /dev/null
            echo "DNS64 添加完成，请确认 DNS 设置生效。"
        else
            echo "跳过 DNS64 添加。"
        fi
    # 支持 IPv4 和 IPv6
    else
        echo "该 VPS 支持 IPv4 和 IPv6，继续安装。"
    fi
fi

# 检测虚拟机类型
if grep -E -q 'openvz' /proc/version; then
    VM_TYPE="openvz"
elif grep -E -q 'lxc' /proc/self/cgroup; then
    VM_TYPE="lxc"
else
    VM_TYPE="none"
fi

echo "检测到虚拟机类型：$VM_TYPE"

# 提示用户是否进行重装
read -p "您需要重装系统吗？（输入 y 进行重装，输入 n 跳过）： " REINSTALL_CHOICE
if [[ "$REINSTALL_CHOICE" == "y" ]]; then
    echo "开始重装系统..."

    # 根据虚拟机类型执行相应操作
    if [[ "$VM_TYPE" == "openvz" ]] || [[ "$VM_TYPE" == "lxc" ]]; then
        echo "检测到虚拟机类型：$VM_TYPE，正在执行 OsMutation 脚本..."
        curl -so OsMutation.sh https://raw.githubusercontent.com/LloydAsp/OsMutation/main/OsMutation.sh
        chmod u+x OsMutation.sh
        ./OsMutation.sh
    else
        echo "未检测到 OpenVZ 或 LXC 虚拟机，直接执行重装脚本..."
        # 执行重装脚本
        curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh || wget -O reinstall.sh $_
        chmod +x reinstall.sh
        ./reinstall.sh debian 11
    fi
else
    echo "跳过重装步骤。"
fi

# 随机生成 SSH 端口，从 10000 开始
RANDOM_PORT=$((RANDOM % (65535 - 10000 + 1) + 10000))  # 生成一个10000到65535之间的随机端口
echo "生成的 SSH 端口为：$RANDOM_PORT"

# 更新 sshd_config 文件
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
echo "正在更新 SSH 配置为端口 $RANDOM_PORT..."
sudo sed -i "s/^#\?Port 22.*/Port $RANDOM_PORT/g" $SSHD_CONFIG_FILE

# 配置 UFW 允许新 SSH 端口
echo "正在允许 UFW 通过 TCP 访问端口 $RANDOM_PORT..."
sudo ufw allow $RANDOM_PORT/tcp

# 确保启用 UFW
if [ "$(sudo ufw status | grep 'Status: inactive')" ]; then
    echo "启用 UFW..."
    sudo ufw enable
else
    echo "重新加载 UFW..."
    sudo ufw reload
fi

# 检查并创建 /var/log/secure 文件
LOGFILE="/var/log/secure"
if [ ! -f "$LOGFILE" ]; then
    echo "$LOGFILE 文件不存在，正在创建..."
    sudo touch "$LOGFILE"
    sudo chmod 600 "$LOGFILE"
    echo "$LOGFILE 文件已创建."
fi

# 下载 SSH 密钥生成脚本并执行
KEY_SCRIPT_URL="https://raw.githubusercontent.com/yuju520/Script/main/key.sh"
echo "正在下载 SSH 密钥生成脚本..."
wget -O key.sh "$KEY_SCRIPT_URL" && chmod +x key.sh

# 提示用户确认生成的密钥已存储
echo "执行密钥生成脚本..."
./key.sh

# 确认密钥生成并提示用户
echo "请确认生成的 SSH 密钥已存储在 ~/.ssh/ 目录下，生成的 SSH 密钥信息请确保已记录和保存。"
read -p "按 [Enter] 键继续..."

# 更新 SSH 配置以禁止密码登录
echo >> $SSHD_CONFIG_FILE
echo "# 禁止密码登录" | sudo tee -a $SSHD_CONFIG_FILE
echo "PasswordAuthentication no" | sudo tee -a $SSHD_CONFIG_FILE
echo "ChallengeResponseAuthentication no" | sudo tee -a $SSHD_CONFIG_FILE

# 更新和升级系统
apt update -y && apt upgrade -y

# 设置时区
sudo timedatectl set-timezone Asia/Shanghai

# 安装必要的软件包
apt install sudo curl wget nano vim socat unzip bash iptables ipset fail2ban ufw -y

# 调用优化脚本
bash <(wget -qO- https://raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -t
bash <(wget -qO- https://raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -x

# 运行优化脚本
wget https://gist.githubusercontent.com/taurusxin/a9fc3ad039c44ab66fca0320045719b0/raw/3906efed227ee14fc5b4ac8eb4eea8855021ef19/optimize.sh
sudo bash optimize.sh

# 安装 TCP 加速脚本
wget -O tcpx.sh "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh"
chmod +x tcpx.sh
./tcpx.sh

# 安装交换空间脚本
wget -O swap.sh https://raw.githubusercontent.com/yuju520/Script/main/swap.sh
chmod +x swap.sh
clear
./swap.sh

# 安装 Docker，判断地区
echo "正在检测 VPS IP 地址..."
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
REGION=$(curl -s https://ipinfo.io/${PUBLIC_IP}/country)

if [[ "$REGION" == "CN" ]]; then
    echo "检测到中国大陆地区，正在从国内源安装 Docker..."
    curl https://install.1panel.live/docker-install -o docker-install
    sudo bash ./docker-install
    rm -f ./docker-install
else
    echo "检测到国外地区，正在从国外源安装 Docker..."
    wget -qO- get.docker.com | bash
fi

# 启用 Docker 服务
sudo systemctl enable docker

# 添加 哪吒探针 监控脚本
echo "正在下载和执行 哪吒探针 监控脚本..."
curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh
chmod +x agent.sh
env NZ_SERVER=pro.licolnlee.top:443 NZ_TLS=true NZ_CLIENT_SECRET=9wRflUL2H7VPoaDXQiSmGdYQSk9vXMYG ./agent.sh

# 添加 IP 黑名单
echo "正在下载和执行 IP 黑名单脚本..."
curl -sS -O https://raw.githubusercontent.com/woniu336/open_shell/main/ipblocker.sh
chmod +x ipblocker.sh
./ipblocker.sh

echo "所有操作已完成。"
