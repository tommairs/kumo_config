--[[---------------------------]]--
-- k_helpers.lua
-- a collection of useful functions
-- to enhance KumoMTA
--[[---------------------------]]--
local mod = {}
local kumo = require 'kumo'
local utils = require 'policy-extras.policy_utils'
local sqlite = require 'sqlite'


---------------------------------------------------------------------
-- Function create_webhook
-- used to create webhook constructors for KumoMTA
-- usage: create_webhook(name,target,user,pass,log_hooks)
-- expects a webhook endpoint using Basic Auth
-- name = webhook name to register
-- target = URL and Port for webhook collector
-- user = HTTP basic username
-- pass = HTTP basic password (unencrypted)
-- log_hooks = log_hooks (exactly as spelled)
---------------------------------------------------------------------
function create_webhook(wh_name,wh_target,basic_user,basic_pass,log_hooks)
 log_hooks:new {
   name = wh_name,
   constructor = function(domain, tenant, campaign)
    local connection = {}
    local client = kumo.http.build_client {}
    function connection:send(message)
      local response = client
        :post(wh_target)
        :header('Content-Type', 'application/json')
        :basic_auth(basic_user,basic_pass)
        :body(message:get_data())
        :send()

      local disposition = string.format(
        '%d %s: %s',
        response:status_code(),
        response:status_reason(),
        response:text()
      )

      if response:status_is_success() then
        return disposition
      end

      kumo.reject(500, disposition)
    end
    return connection
  end,
}
end

-------------------------------------------------------------  
-- sqlite_auth_checker
-- Used to check user and password credentials from a local sqlite db
-- db is expected to have two text fields called email and password
-- Note that the "email" field is just text with no format validation
-------------------------------------------------------------  
function sqlite_auth_check(user, password)
    local db = sqlite.open '/home/myaccount/mypswd.db'
    local result = db:execute ('select * from users where email=? and password=?', user,password)

    -- if any rows are returned, it was because we found a match
    if #result == 1 then
      return true
    else
      return false
    end
  end


-----------------------------------------------------------------------
--[[ Local Function printTableF() ]]--
-- Used to pretty print any sized table in Lua
-- but in this case it writes to an external file
-- This could be resource intensive so only use it for debugging
-------------------------------------------------------------------------
function k_printTableF( filename, t )
    local fh = io.open(filename,"a")
    local printTable_cache = {}

    local function sub_printTable( t, indent, filename )

        if ( printTable_cache[tostring(t)] ) then
            fh:write( indent .. "*" .. tostring(t) )
            fh:write("\n")
        else
            printTable_cache[tostring(t)] = true
            if ( type( t ) == "table" ) then
                for pos,val in pairs( t ) do
                    if ( type(val) == "table" ) then
                        fh:write( indent .. "[" .. pos .. "] => " .. tostring( t ).. " {" )
                        fh:write("\n")
                        sub_printTable( val, indent .. string.rep( " ", string.len(pos)+8 ), filename )
                        fh:write( indent .. string.rep( " ", string.len(pos)+6 ) .. "}" )
                        fh:write("\n")
                elseif ( type(val) == "string" ) then
                        fh:write( indent .. "[" .. pos .. '] => "' .. val .. '"' )
                        fh:write("\n")
                    else
                        fh:write( indent .. "[" .. pos .. "] => " .. tostring(val) )
                        fh:write("\n")
                    end
                end
            else
                fh:write( indent..tostring(t) )
                fh:write("\n")
            end
        end
    end

    if ( type(t) == "table" ) then
        fh:write( tostring(t) .. " {" )
        fh:write("\n")
        sub_printTable( t, "  ", filename )
        fh:write( "}" )
        fh:write("\n")
    else
        sub_printTable( t, "  ",filename )
    end
    fh:write("\n")
    fh:close()

end

--[[ isempty() is a shortcut to eval if a varualble is nill or no value ]]--
function isempty(s)
    return s == nil or s == ''
end

--[[ Extract the x-tenant header value and addign it to the tenant variable ]]--
-- function set_tenant_by_X()
function set_tenant_by_X(headername)
  local headers = message:get_all_headers()
  local tenant = "default"
  if headers[headername] == high then
    tenant = "priority"
  end
  return tenant
end


--[[ Print a text string to a local file ]]--
-- function k_print(fname,text)
function k_print(fname,text)
  fh = io.open(fname,"a")
  fh:write(text)
  fh:close()
end


function table.contains(table, element)
  for _, value in pairs(table) do
    if value == element then
      return true
    end
  end
  return false

end




