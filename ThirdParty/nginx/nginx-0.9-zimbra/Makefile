
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile
	$(MAKE) -f objs/Makefile manpage

install:
	$(MAKE) -f objs/Makefile install

upgrade:
	/opt/zimbra/nginx-0.9-zimbra/sbin/nginx -t

	kill -USR2 `cat /opt/zimbra/nginx-0.9-zimbra/logs/nginx.pid`
	sleep 1
	test -f /opt/zimbra/nginx-0.9-zimbra/logs/nginx.pid.oldbin

	kill -QUIT `cat /opt/zimbra/nginx-0.9-zimbra/logs/nginx.pid.oldbin`
