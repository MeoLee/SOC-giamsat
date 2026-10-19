#!/bin/sh
set -eu
mkdir -p /run/mysqld /var/log/mysql
chown mysql:mysql /run/mysqld /var/log/mysql
if ! mariadb-admin --protocol=socket --socket=/run/mysqld/mysqld.sock ping --silent >/dev/null 2>&1; then
    if [ ! -d /var/lib/mysql/mysql ]; then
        mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=socket
    fi
    mariadbd --user=mysql --datadir=/var/lib/mysql --socket=/run/mysqld/mysqld.sock \
        --pid-file=/run/mysqld/mysqld.pid --bind-address=127.0.0.1 \
        --log-error=/var/log/mysql/soc-lab-error.log \
        </dev/null >>/var/log/mysql/soc-lab-start.log 2>&1 &
fi
web_ready=no
for web_try in $(seq 1 30); do
    if mariadb-admin --protocol=socket --socket=/run/mysqld/mysqld.sock ping --silent >/dev/null 2>&1; then
        web_ready=yes
        break
    fi
    sleep 1
done
if [ "$web_ready" != yes ]; then
    tail -n 30 /var/log/mysql/soc-lab-error.log >&2
    exit 1
fi
apache2ctl configtest
if pgrep -f '^/usr/sbin/apache2([[:space:]]|$)' >/dev/null; then
    apache2ctl -k graceful
else
    apache2ctl -k start
fi
