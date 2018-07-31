---- Based from https://github.com/StephenPCG/nginx-lua-simpleauth-module/blob/master/simpleauthn_cookie.lua
--   secret_key: a secret_key to protect bad user from forging fake authentication hash.
--   auth_url_fmt: it is used to jump to real auth method on authn fail.

local secret_key = 'please call nginxauth.set_secret_key() to change this key!'
local auth_url_fmt = '/nginx_auth/?%s'
local white_ipv4_list = {}
local white_ipv6_list = {}
local behind_proxy = false

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
local function set_white_ipv4_list (v4_list)
    white_ipv4_list = v4_list
end

local function set_white_ipv6_list (v6_list)
    white_ipv6_list = v6list
end

local function  set_behind_proxy (v)
    behind_proxy = v
end

local function access ()
    local headers=ngx.req.get_headers()
    local clientip=""
    if behind_proxy then
        clientip=headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    else
        clientip=ngx.var.remote_addr or "0.0.0.0"
    end
    ngx.log(ngx.ERR,"ip="..clientip)   
    if string.find(clientip,":") then  -- IPv6 client
	if #white_ipv6_list >= 1 then
            for i=1, #white_ipv6_list - 1 do
                if string.find(clientip,white_ipv6_list[i]) ~= nil then
                    return
		end
            end
	end
    else  -- check IPv4
	if #white_ipv4_list >= 2 then
            for i=1, #white_ipv4_list - 1, 2 do
               ngx.log(ngx.ERR,"i="..i)
               if (ip2num(clientip)>=ip2num(white_ipv4_list[i])) and (ip2num(clientip)<=ip2num(white_ipv4_list[i+1])) then
                   ngx.log(ngx.ERR,"white_ip")
                   return
               end
	    end
        end
    end
    uid = get_uid()
    if uid == nil then
        ngx.header['Location'] = get_auth_url()
        ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end
end

local P = {
    set_secret_key = set_secret_key,
    set_auth_url_fmt = set_auth_url_fmt,
    set_white_ipv4_list = set_white_ipv4_list,
    set_white_ipv6_list = set_white_ipv6_list,
    set_behind_proxy = set_behind_proxy,
    access = access
}

return P

