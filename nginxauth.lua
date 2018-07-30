---- From https://github.com/StephenPCG/nginx-lua-simpleauth-module/blob/master/simpleauthn_cookie.lua
-- There are several options to make the authn stronger.
--   secret_key: a secret_key to protect bad user from forging fake authentication hash.
--   hash_func:  a function receives a string and output a digest string which will be stored
--               in user browser.
--   auth_url_fmt: it is used to jump to real auth method on authn fail.

local secret_key = 'please call nginxauth.set_secret_key() to change this key!'
local auth_url_fmt = '/nginx_auth/?%s'
local hash_func = ngx.md5

local function set_secret_key (key)
    secret_key = key
end

local function set_auth_url_fmt (fmt)
    auth_url_fmt = fmt
end

local function set_hash_func (func)
    hash_func = func
end

local function calc_hash(uid, expire, ...)
    hashdata = secret_key .. '|' .. uid .. '|' .. expire .. '|'
    for _, k in pairs({...}) do
        hashdata = hashdata .. k .. '|'
    end
    return hash_func(hashdata)
end

local function get_uid (...)
    -- call this function to get authenticated uid, if not authenticated, return nil
    uid = ngx.var.cookie_nginx_auth_uid
    hash = ngx.var.cookie_nginx_auth_hash
    expire = ngx.var.cookie_nginx_auth_expire
    if uid ~= nil and hash ~= nil and expire ~= nil and
        ngx.req.start_time() < tonumber(expire) and
        hash == calc_hash(uid, expire, ...) then
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

local function access (...)
    -- do simple auth process, all 'logged in' will be authorized, 'non-logged in' user will
    uid = get_uid(...)
    if uid == nil then
        ngx.header['Location'] = get_auth_url()
        ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end
end

local P = {
    set_secret_key = set_secret_key,
    set_auth_url_fmt = set_auth_url_fmt,
    set_hash_func = set_hash_func,
    get_auth_url = get_auth_url,
    get_uid = get_uid,
    access = access
}

return P

