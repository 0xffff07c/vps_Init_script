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
        read -p "您是否需要开启 Warp 支持？（输入 y 进行开启，输入 n 跳过）： " WARP_CHOICE
        if [[ "$WARP_CHOICE" == "y" ]]; then
            echo "正在开启 Warp 支持（参数: 4）..."
            wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh 4 || echo "开启 Warp 支持失败，继续执行其他操作..."
        fi
    # 仅支持 IPv6
    elif [[ "$IPV4" == "no" && "$IPV6" == "yes" ]]; then
        echo "该 VPS 仅支持 IPv6。"
        read -p "建议您添加 DNS64，以方便下载 IPv4 下的资源。是否继续？（输入 y 进行添加，输入 n 跳过）： " DNS64_CHOICE
        if [[ "$DNS64_CHOICE" == "y" ]]; then
            echo "正在添加 DNS64..."
            echo -e "nameserver 2606:4700:4700::64\nnameserver 2606:4700:4700::6400" | sudo tee /etc/resolv.conf > /dev/null
            echo "DNS64 添加完成，请确认 DNS 设置生效。"
        fi

        read -p "您是否需要开启 Warp 支持？（输入 y 进行开启，输入 n 跳过）： " WARP_CHOICE
        if [[ "$WARP_CHOICE" == "y" ]]; then
            echo "正在开启 Warp 支持（参数: 6）..."
            wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh 6 || echo "开启 Warp 支持失败，继续执行其他操作..."
        fi
    # 支持 IPv4 和 IPv6
    else
        echo "该 VPS 支持 IPv4 和 IPv6，继续安装。"
    fi
fi
# 检测虚拟机类型
if command -v systemd-detect-virt &> /dev/null; then
    VM_TYPE=$(systemd-detect-virt)
else
    echo "未检测到 systemd-detect-virt 命令，采用其他方式检测。"

    # 提示用户是否进行重装
    read -p "您需要重装系统吗？（输入 y 进行重装，输入 n 跳过）： " REINSTALL_CHOICE
    if [[ "$REINSTALL_CHOICE" == "y" ]]; then
        echo "开始重装系统..."
        
        # 检测虚拟机类型
        if grep -E -q 'openvz' /proc/version; then
            VM_TYPE="openvz"
        elif grep -E -q 'lxc' /proc/self/cgroup; then
            VM_TYPE="lxc"
        else
            VM_TYPE="none"
        fi
    fi
fi

echo "检测到虚拟机类型：$VM_TYPE"


# 提示用户是否进行重装
read -p "您需要重装系统吗？（输入 y 进行重装，输入 n 跳过）： " REINSTALL_CHOICE
if [[ "$REINSTALL_CHOICE" == "y" ]]; then
    echo "开始重装系统..."

    # 根据虚拟机类型执行相应操作
    if [[ "$VM_TYPE" == "openvz" ]] || [[ "$VM_TYPE" == "lxc" ]]; then
        echo "检测到虚拟机类型：$VM_TYPE，正在执行 OsMutation 脚本..."
        curl -so OsMutation.sh https://ghfast.top/raw.githubusercontent.com/LloydAsp/OsMutation/main/OsMutation.sh
        chmod u+x OsMutation.sh
        ./OsMutation.sh || echo "OsMutation 脚本执行失败，继续执行其他操作..."
    else
        echo "未检测到 OpenVZ 或 LXC 虚拟机，直接执行重装脚本..."
        # 执行重装脚本
        curl -O https://gitlab.com/bin456789/reinstall/-/raw/main/reinstall.sh || wget -O reinstall.sh $_
        chmod +x reinstall.sh
        ./reinstall.sh debian 12
        if [[ $? -eq 0 ]]; then
            echo "重装脚本执行成功！"
            read -p "是否立即重启 VPS？（输入 y 进行重启，输入 n 取消）： " REBOOT_CHOICE
            if [[ "$REBOOT_CHOICE" == "y" ]]; then
                echo "正在重启系统..."
                reboot
            else
                echo "您选择跳过重启，继续其他操作..."
            fi
        else
            echo "重装脚本执行失败，继续执行其他操作..."
        fi
        # ./reinstall.sh debian 11 || echo "重装脚本执行失败，继续执行其他操作..."
    fi
else
    echo "跳过重装步骤。"
fi

# 更新和升级系统
echo "正在更新和升级系统..."
apt update -y && apt upgrade -y

# 设置时区
sudo timedatectl set-timezone Asia/Shanghai

# 安装必要的软件包
apt install sudo curl wget nano vim socat unzip bash iptables ipset fail2ban ufw knockd cron netcat-openbsd -y

# 随机生成 SSH 端口，从 10000 开始
RANDOM_PORT=$((RANDOM % (65535 - 10000 + 1) + 10000))  # 生成一个10000到65535之间的随机端口
echo "生成的 SSH 端口为：$RANDOM_PORT"

# 更新 sshd_config 文件
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
echo "正在更新 SSH 配置为端口 $RANDOM_PORT..."
sudo sed -i "s/^#\?Port 22.*/Port $RANDOM_PORT/g" $SSHD_CONFIG_FILE

# 配置 Fail2ban 的 jail.local 文件
echo "正在配置 Fail2ban 以保护 SSH 的端口 $RANDOM_PORT..."
sudo bash -c "cat <<EOL > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 86400
findtime = 86400
maxretry = 3

[sshd]
enabled = true
port = $RANDOM_PORT
filter = sshd
action = iptables[name=SSH, port=$RANDOM_PORT, protocol=tcp]
logpath = /var/log/auth.log
EOL"

# 重启 SSH 和 Fail2ban 服务
echo "重启 SSH 服务以应用新的端口 ($RANDOM_PORT)"
sudo systemctl restart sshd
echo "重启 Fail2ban 服务以加载新的配置"
sudo systemctl restart fail2ban

# 检查重新生成的配置状态
echo "检查 Fail2ban 和 SSH 配置状态..."
sudo fail2ban-client status
sudo fail2ban-client status sshd
echo "随机 SSH 端口 ($RANDOM_PORT) 已成功配置并生效！"

# 检查并创建 /var/log/auth.log 文件
LOGFILE="/var/log/auth.log"
if [ ! -f "$LOGFILE" ]; then
    echo "$LOGFILE 文件不存在，正在创建..."
    sudo touch "$LOGFILE"
    sudo chmod 600 "$LOGFILE"
    echo "$LOGFILE 文件已创建."
fi

# 配置 UFW 允许新 SSH 端口
echo "正在允许 UFW 通过 TCP 访问端口 $RANDOM_PORT..."
sudo ufw allow $RANDOM_PORT/tcp

# 随机生成敲门次数，允许范围为 3 至 5
KNOCK_COUNT=$((RANDOM % 3 + 3))  # 生成 3 至 5 的随机数
KNOCK_PORTS=()

# 动态生成敲门所需的端口
for ((i = 1; i <= KNOCK_COUNT; i++)); do
    KNOCK_PORTS+=($((RANDOM % (65535 - 10000 + 1) + 10000)))
done

# 动态生成敲门序列
KNOCKD_SEQUENCE_OPEN=$(IFS=,; echo "${KNOCK_PORTS[*]}")  # 敲门开启序列
KNOCKD_SEQUENCE_CLOSE=$(IFS=,; echo "${KNOCK_PORTS[*]}" | awk -F, '{for(i=NF; i>=1; i--) printf $i (i>1?",":"")}')  # 敲门关闭序列

# 输出敲门配置到终端
echo "敲门配置生成成功，请记录以下详细信息："
echo "敲门次数: $KNOCK_COUNT"
echo "敲门开启序列: $KNOCKD_SEQUENCE_OPEN"
echo "敲门关闭序列: $KNOCKD_SEQUENCE_CLOSE"
echo "敲门所需端口: ${KNOCK_PORTS[*]}"
echo "敲门配置将在自动写入 knockd 的配置文件中。"
read -p "按下 [Enter] 键确认已记录所有信息，继续执行下一步..."

# 配置 UFW 允许敲门所需的端口
echo "正在允许 UFW 放行敲门所需的端口..."
for PORT in "${KNOCK_PORTS[@]}"; do
    sudo ufw allow $PORT/tcp
done

# 检查 UFW 状态并应用规则
UFW_STATUS=$(sudo ufw status | grep "Status:" | awk '{print $2}')
if [[ "$UFW_STATUS" == "inactive" ]]; then
    echo "UFW 当前未激活，正在启用 UFW..."
    sudo ufw enable
else
    echo "UFW 当前已激活，正在重载 UFW..."
    sudo ufw reload
fi

# 写入 knockd 配置文件
echo "正在配置 knockd 服务..."
sudo bash -c "cat <<EOL > /etc/knockd.conf
[options]
    UseSyslog
    logfile = /var/log/knockd.log
# 开启SSH访问 - 只允许敲门的IP访问
[openSSH]
    sequence = $KNOCKD_SEQUENCE_OPEN
    seq_timeout = 15
    start_command = /sbin/iptables -C INPUT -s %IP% -p tcp --dport $RANDOM_PORT -j ACCEPT || /sbin/iptables -I INPUT 1 -s %IP% -p tcp --dport $RANDOM_PORT -j ACCEPT || /sbin/ip6tables -I INPUT 1 -s %IP% -p tcp --dport $RANDOM_PORT -j ACCEPT || /sbin/ip6tables -C INPUT -s %IP% -p tcp --dport $RANDOM_PORT -j ACCEPT
    tcpflags    = syn
    cmd_timeout = 10
# 关闭所有SSH访问 - 阻止所有IP
[closeSSH]
    sequence = $KNOCKD_SEQUENCE_CLOSE
    seq_timeout = 15
    start_command = /sbin/iptables -C INPUT -p tcp --dport $RANDOM_PORT -j DROP || /sbin/iptables -I INPUT 1 -p tcp --dport $RANDOM_PORT -j DROP && /sbin/iptables -D INPUT -s %IP% -p tcp --dport $RANDOM_PORT -j ACCEPT 2>/dev/null || /sbin/ip6tables -C INPUT -p tcp --dport $RANDOM_PORT -j DROP || /sbin/ip6tables -I INPUT 1 -p tcp --dport $RANDOM_PORT -j DROP && /sbin/ip6tables -D INPUT -s %IP% -p tcp --dport $RANDOM_PORT -j ACCEPT 2>/dev/null
    tcpflags    = syn
    cmd_timeout = 10
    
EOL"

# 启动 knockd 服务
sudo systemctl enable knockd
sudo systemctl start knockd
echo "敲门服务配置完成并已启动！"

# 启动 SSH 服务
sudo systemctl restart sshd

# 下载 SSH 密钥生成脚本并执行
KEY_SCRIPT_URL="https://ghfast.top/raw.githubusercontent.com/yuju520/Script/main/key.sh"
echo "正在下载 SSH 密钥生成脚本..."
wget -O key.sh "$KEY_SCRIPT_URL" && chmod +x key.sh

# 提示用户确认生成的密钥已存储
echo "执行密钥生成脚本..."
./key.sh

# 等待用户确认密钥信息
echo "SSH 密钥已生成，请确保已记录好密钥信息！"
echo "SSH 端口: $RANDOM_PORT"
echo "SSH 密钥已生成在 ~/.ssh/ 目录中。"

# 等待用户确认
read -p "请确认已存储 SSH 密钥与端口信息，按 [Enter] 键继续..."

# 更新 SSH 配置以禁止密码登录
echo >> $SSHD_CONFIG_FILE
echo "# 禁止密码登录" | sudo tee -a $SSHD_CONFIG_FILE
echo "PasswordAuthentication no" | sudo tee -a $SSHD_CONFIG_FILE
echo "ChallengeResponseAuthentication no" | sudo tee -a $SSHD_CONFIG_FILE

# 运行优化脚本
wget https://ghfast.top/gist.githubusercontent.com/taurusxin/a9fc3ad039c44ab66fca0320045719b0/raw/3906efed227ee14fc5b4ac8eb4eea8855021ef19/optimize.sh
sudo bash optimize.sh

# 安装优化工具
bash <(wget -qO- https://ghfast.top/raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -t
# 检测虚拟机类型
if command -v systemd-detect-virt &> /dev/null; then
    VM_TYPE=$(systemd-detect-virt)

    if [[ "$VM_TYPE" == "lxc" ]]; then
        echo "检测到虚拟化环境为 LXC，脚本不支持运行于该环境。"
        echo "跳过 Tune 脚本 (-x) 的执行，继续其他操作..."
    else
        echo "当前虚拟机类型为：$VM_TYPE"
        echo "虚拟机类型支持，继续执行 Tune 脚本 (-x)。"
        # 执行 Tune 脚本
        bash <(wget -qO- https://ghfast.top/raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -x
    fi
else
    echo "未检测到虚拟化环境，继续执行 Tune 脚本 (-x)。"
    # 执行 Tune 脚本
    bash <(wget -qO- https://ghfast.top/raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -x
fi

# 继续执行其他脚本项...
echo "其他脚本操作继续进行..."


# # 安装 TCP 加速脚本
# wget -O tcpx.sh "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh"
# chmod +x tcpx.sh
# ./tcpx.sh

# 安装交换空间脚本
wget -O swap.sh https://ghfast.top/raw.githubusercontent.com/yuju520/Script/main/swap.sh
chmod +x swap.sh
clear
./swap.sh

# 检测系统内存大小
echo "正在检测系统的内存大小..."
TOTAL_MEMORY=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
# 转换为 MB（因为 /proc/meminfo 单位是 KB）
TOTAL_MEMORY_MB=$((TOTAL_MEMORY / 1024))
echo "当前系统总内存大小为：${TOTAL_MEMORY_MB} MB"

# 基于内存大小给出建议
if [[ "$TOTAL_MEMORY_MB" -lt 512 ]]; then
    echo "检测到系统内存较小（小于 512MB），建议不要安装 Docker，以免导致性能问题。"
elif [[ "$TOTAL_MEMORY_MB" -lt 1024 ]]; then
    echo "检测到系统内存低（小于 1024MB），安装 Docker 后可能会影响系统性能，请谨慎选择。"
else
    echo "系统内存充足，可以安装 Docker。"
fi

# 提示用户是否安装 Docker
read -p "您是否要安装 Docker？（输入 y 表示安装，输入 n 表示跳过）： " INSTALL_DOCKER_CHOICE

if [[ "$INSTALL_DOCKER_CHOICE" == "y" ]]; then
    # 安装 Docker，判断地区
    echo "正在检测 VPS IP 地址..."
    PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
    REGION=$(curl -s https://ipinfo.io/${PUBLIC_IP}/country)

    if [[ "$REGION" == "CN" ]]; then
        echo "检测到中国大陆地区，正在从国内源安装 Docker..."
        curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
    else
        echo "检测到国外地区，正在从国外源安装 Docker..."
        wget -qO- get.docker.com | bash
    fi

    # 启用 Docker 服务
    sudo systemctl enable docker
    echo "Docker 安装完成并已启用服务！"
else
    echo "跳过 Docker 安装逻辑。"
fi

echo "继续执行脚本的其他操作..."

# 添加 哪吒探针 监控脚本
echo "正在下载和执行 哪吒探针 监控脚本..."
curl -L https://ghfast.top/raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh
chmod +x agent.sh
env NZ_SERVER=pro.licolnlee.top:443 NZ_TLS=true NZ_CLIENT_SECRET=9wRflUL2H7VPoaDXQiSmGdYQSk9vXMYG ./agent.sh

# 检查用户是否之前安装过哪吒探针
read -p "您这台 VPS 之前是否安装过哪吒探针？（输入 y 表示是，输入 n 表示否）： " NEZHA_CHOICE

if [[ "$NEZHA_CHOICE" == "y" ]]; then
    echo "停止哪吒探针服务..."
    sudo systemctl stop nezha-agent
    
    # 输入 UUID
    read -p "请输入您的 VPS UUID： " USER_UUID
    
    # 更新 UUID
    CONFIG_FILE="/opt/nezha/agent/config.yml"
    if grep -q 'uuid:' "$CONFIG_FILE"; then
        sudo sed -i "s/uuid: .*/uuid: $USER_UUID/" "$CONFIG_FILE"
        echo "UUID 更新成功！"
    else
        echo "配置文件中未找到 UUID 项。"
    fi
    
    # 询问是否启用 IPv6 验证国家属地
    read -p "是否需要启用通过 IPv6 验证国家属地？（输入 y 表示启用，输入 n 表示跳过）： " IPV6_COUNTRY_CHOICE
    if [[ "$IPV6_COUNTRY_CHOICE" == "y" ]]; then
        if grep -q 'use_ipv6_country_code:' "$CONFIG_FILE"; then
            sudo sed -i "s/use_ipv6_country_code:.*/use_ipv6_country_code: true/" "$CONFIG_FILE"
            echo "已启用通过 IPv6 验证国家属地。"
        else
            echo "配置文件中未找到 use_ipv6_country_code 项，无法修改。"
        fi
    else
        echo "跳过启用通过 IPv6 验证国家属地。"
    fi

    # 启动哪吒探针服务
    sudo systemctl start nezha-agent
else
    echo "未安装哪吒探针，无需处理。"
fi


# 添加 IP 黑名单
echo "正在下载和执行 IP 黑名单脚本..."
curl -sS -O https://ghfast.top/https://raw.githubusercontent.com/0xffff07c/open_shell/refs/heads/main/ipblocker.sh
chmod +x ipblocker.sh
./ipblocker.sh

# 询问是否重启
read -p "所有操作已完成。您是否需要重启 VPS？（输入 y 进行重启，输入 n 跳过）： " REBOOT_CHOICE
if [[ "$REBOOT_CHOICE" == "y" ]]; then
    echo "正在重启 VPS..."
    sudo reboot
else
    echo "请记得后续自行重启您的 VPS。"
fi
