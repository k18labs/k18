#!/usr/bin/env bash
# Run on the server while it runs Linux (ssh root@server 'bash -s' < bench/setup-nginx.sh
# after copying bench/nginx.conf, the page and the identity: see bench/README.md): nginx
# with bench/nginx.conf, and a kernel that is not the limit before nginx is.
set -e
export DEBIAN_FRONTEND=noninteractive
command -v nginx >/dev/null || { apt-get update -qq; apt-get install -y -qq nginx-light >/dev/null; }
mkdir -p /etc/nginx/k18bench /var/www/k18bench
cp /root/k18bench/server.pem /root/k18bench/server.key /etc/nginx/k18bench/
chmod 600 /etc/nginx/k18bench/server.key
cp /root/k18bench/index.html /var/www/k18bench/index.html
cp /root/k18bench/nginx.conf /etc/nginx/nginx.conf
sysctl -q -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 net.core.netdev_max_backlog=65535 \
  fs.file-max=4000000 fs.nr_open=2000000 net.ipv4.tcp_max_orphans=1000000 net.ipv4.tcp_tw_reuse=1
# one receive queue, two processors: let the kernel spread the packets over both (RPS),
# as k18 does itself
for q in /sys/class/net/e*/queues/rx-*; do echo 3 > $q/rps_cpus; done
mkdir -p /etc/systemd/system/nginx.service.d
printf '[Service]\nLimitNOFILE=1048576\n' > /etc/systemd/system/nginx.service.d/limits.conf
systemctl daemon-reload
nginx -t 2>&1 | tail -1
systemctl restart nginx
nginx -v 2>&1; openssl version; ps -o pid,rss,args -C nginx | head -5
