---- Based from https://github.com/StephenPCG/nginx-lua-simpleauth-module/blob/master/simpleauthn_cookie.lua
--   secret_key: a secret_key to protect bad user from forging fake authentication hash.
--   auth_url_fmt: it is used to jump to real auth method on authn fail.

local secret_key = 'please call nginxauth.set_secret_key() to change this key!'
local auth_url_fmt = '/nginx_auth/?%s'

local function set_secret_key (key)
    secret_key = key
end

local function set_auth_url_fmt (fmt)
    auth_url_fmt = fmt
end

local function get_uid (...)
    -- call this function to get authenticated uid, if not authenticated, return nil
    uid = ngx.var.cookie_nginx_auth_uid
    hash = ngx.var.cookie_nginx_auth_hash
    expire = ngx.var.cookie_nginx_auth_expire
    if uid ~= nil and hash ~= nil and expire ~= nil and
        ngx.req.start_time() < tonumber(expire) and
        hash == ngx.md5(secret_key .. '|' .. uid .. '|' .. expire) then
            return uid
    end
    return nil
end

local function get_current_url ()
    return ngx.escape_uri(ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.request_uri)
end

local function get_auth_url ()
    return string.format(auth_url_fmt, "next=" .. get_current_url())
end

local function ip2num (ip)
    local o1,o2,o3,o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )
    return 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
end

local ustc_ip = {
"202.38.64.0", "202.38.95.255"
}

local function access (...)
    local headers=ngx.req.get_headers()
    local clientip=headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    ngx.log(ngx.ERR,"ip="..clientip)   
    for i=1, #ustc_ip do
       nginx.log(nginx.ERR,"i="..i)
       if (ip2num(clientip)>=ip2num(ustc_ip[i]) and (ip2num(clientip)<=ip2num(ustc_ip[i+1])) then
           nginx.log(nginx.ERR,"ustc_ip")
           return
       end
       i = i + 1
    end
    uid = get_uid(...)
    if uid == nil then
        ngx.header['Location'] = get_auth_url()
        ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end
end

local P = {
    set_secret_key = set_secret_key,
    set_auth_url_fmt = set_auth_url_fmt,
    access = access
}

return P

