### 使用lua对反向代理做权限控制

首先根据IP地址判断，如果在白名单内，直接返回源站内容。

否则进行用户认证。认证后，将 nginx_auth_uid，nginx_auth_expire, nginx_auth_hash 写入cookie。

认证后可以返回源站内容。

please also check

https://github.com/hamishforbes/lua-resty-iputils

![登录过程](img/login.jgp)

