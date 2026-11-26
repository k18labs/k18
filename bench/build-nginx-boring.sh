#!/usr/bin/env bash
# Run on a machine with the server's Ubuntu (a load generator will do; the server's two
# processors take much longer): nginx from nginx.org's source, linked against BoringSSL as
# it is today. Leaves /root/nginx-boring (stripped, 3.6 MB). On the server it runs with
# bench/nginx.conf as the packaged nginx does:
#   mkdir -p /opt/nginx-boring/sbin /opt/nginx-boring/logs
#   cp nginx-boring /opt/nginx-boring/sbin/nginx
#   systemctl stop nginx; /opt/nginx-boring/sbin/nginx -c /etc/nginx/nginx.conf
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential cmake ninja-build git libpcre2-dev zlib1g-dev curl >/dev/null
cd /root
[ -d boringssl ] || git clone -q --depth 1 https://boringssl.googlesource.com/boringssl
cd boringssl
git log -1 --format='boringssl %H %cd' --date=short
cmake -GNinja -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C build ssl crypto >/dev/null
cd /root
V=$(curl -s https://nginx.org/download/ | grep -o 'nginx-1\.28\.[0-9]*\.tar\.gz' | sort -V | tail -1)
echo "nginx source: $V"
[ -f "$V" ] || curl -s -O "https://nginx.org/download/$V"
rm -rf nginx-src && mkdir nginx-src && tar -xzf "$V" -C nginx-src --strip-components 1
cd nginx-src
# BoringSSL's archives need the C++ runtime, and nginx puts our options in front of them:
# without --no-as-needed the linker has dropped libstdc++ by the time they ask for it.
./configure --prefix=/opt/nginx-boring --with-http_ssl_module --with-threads \
  --without-http_gzip_module --without-http_rewrite_module \
  --with-cc-opt="-O2 -I/root/boringssl/include" \
  --with-ld-opt="-L/root/boringssl/build -Wl,--no-as-needed -lstdc++ -Wl,--as-needed -lpthread" \
  >/root/nginx-configure.log 2>&1 || { tail -20 /root/nginx-configure.log; exit 1; }
make -j"$(nproc)" >/root/nginx-make.log 2>&1 || { tail -30 /root/nginx-make.log; exit 1; }
strip -o /root/nginx-boring objs/nginx
objs/nginx -V 2>&1 | head -3
ls -la /root/nginx-boring
