#!/bin/bash
PATH=/sbin:/usr/sbin:/bin:/usr/bin
###########################################################
# iptables Defense DDOS Linux Shell By Wending
# Wending <ilidangao@gmail.com>
#
# Best iptables solution
# Defense against all kinds of attacks
# To provide security for escort
###########################################################


# 优化系统
echo net.ipv4.tcp_syncookies = 1 >/etc/sysctl.conf
echo net.ipv4.tcp_fin_timeout = 1 >>/etc/sysctl.conf
echo net.ipv4.tcp_tw_reuse = 1 >>/etc/sysctl.conf
echo net.ipv4.tcp_max_tw_buckets = 6000 >>/etc/sysctl.conf
echo net.ipv4.tcp_tw_recycle = 1 >>/etc/sysctl.conf
echo net.ipv4.tcp_syn_retries = 1 >>/etc/sysctl.conf
echo net.ipv4.tcp_synack_retries = 1 >>/etc/sysctl.conf
echo net.ipv4.tcp_max_syn_backlog = 262144 >>/etc/sysctl.conf
echo net.core.netdev_max_backlog = 262144 >>/etc/sysctl.conf
echo net.ipv4.tcp_max_orphans = 262144 >>/etc/sysctl.conf
echo net.ipv4.tcp_keepalive_time = 30 >>/etc/sysctl.conf
sysctl -p


# 清理所有规则
iptables -F
iptables -X
iptables -Z


# 设置默认策略
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT


# 允许回环 
iptables -A INPUT -i lo -j ACCEPT


# 允许通行端口
iptables -A INPUT  -p tcp -j ACCEPT -m multiport --dport 80,443,3312,3313,13141,14126,41261,43458,55090


# 允许由服务器本身请求的数据通过
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT  
# iptables -A INPUT -m state --state ESTABLISHED,RELATED -m tcp -p tcp --dport 22 -j ACCEPT


# 允许单个IP访问服务器的80端口的最大连接数为 20 
iptables -I INPUT -p tcp --dport 80 -m connlimit  --connlimit-above 20 -j REJECT 


# 抵御DDOS ，允许外网最多24个初始连接,然后服务器每秒新增12个，访问太多超过的丢弃，第二条是允许服务器内部每秒1个初始连接进行转发
iptables -A INPUT  -p tcp --syn -m limit --limit 12/s --limit-burst 24 -j ACCEPT
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT


# 对访问本机的22端口进行限制，每个ip每小时只能连接5次，超过的拒接，1小时候重新计算次数
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --name SSHPOOL --rcheck --seconds 3600 --hitcount 5 -j DROP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --name SSHPOOL --set -j ACCEPT
#（上面recent规则只适用于默认规则为DROP中，如果要适用默认ACCEPT的规则，需要--set放前面 并且无-j ACCEPT）


# 防止DDOS攻击：Ping of Death
iptables -N PING_OF_DEATH
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request \
-m hashlimit \
--hashlimit 10/s \
--hashlimit-burst 10 \
--hashlimit-htable-expire 300000 \
--hashlimit-mode srcip \
--hashlimit-name t_PING_OF_DEATH \
-j RETURN
iptables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death_attack: "
iptables -A PING_OF_DEATH -j DROP
iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH


# 防止DDOS攻击：SYN FLOOD
iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -p tcp --syn \
-m hashlimit \
--hashlimit 200/s \
--hashlimit-burst 10 \
--hashlimit-htable-expire 300000 \
--hashlimit-mode srcip \
--hashlimit-name t_SYN_FLOOD \
-j RETURN
iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
iptables -A SYN_FLOOD -j DROP
iptables -A INPUT -p tcp --syn -j SYN_FLOOD


# 防止DDOS攻击：stealth scan
iptables -N STEALTH_SCAN
iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
iptables -A STEALTH_SCAN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN

# Centos 6
chkconfig iptables on
# Centos 7
systemctl enable iptables.service

service iptables save
service iptables restart

systemctl restart iptables.service
