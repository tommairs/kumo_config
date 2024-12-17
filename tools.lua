--[[---------------------------]]--
-- toools.lua
-- a collection of useful functions
-- to enhance KumoMTA
--[[---------------------------]]--
local name = "tools"
local mod = { }
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
--
-- Note that it is probably better to use the Kumo built-in helper function for this
-- https://docs.kumomta.com/userguide/operation/webhooks/?h=webhook#using-the-log_hookslua-helper
--
function mod.create_webhook(wh_name,wh_target,basic_user,basic_pass,log_hooks)
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


	print ("Shipping Webhook: " .. wh_name )

      local disposition = string.format(
        '%d %s: %s',
        response:status_code(),
        response:status_reason(),
        response:text()
      )
print ("Disposition : " .. disposition )

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
function mod.sqlite_auth_check(user, password)
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
function mod.k_printTableF( filename, t )
--	local filename = "/tmp/temptable"
    local fh = io.open(filename, "a")
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

--[[ isempty() is a shortcut to eval if a variable is nill or no value ]]--
function mod.isempty(s)
    return s == nil or s == ''
end

--[[ Extract the x-tenant header value and assign it to the tenant variable ]]--
-- function set_tenant_by_X()
function mod.set_tenant_by_X(headername)
  local headers = message:get_all_headers()
  local tenant = "default"
  if headers[headername] == high then
    tenant = "priority"
  end
  return tenant
end


--[[ Print a text string to a local file ]]--
-- function k_print(fname,text)
function mod.k_print(fname,text)
  fh = io.open(fname,"a")
  fh:write(text)
  fh:close()
end


function mod.table_contains_a(table, value)
  for i = 1,#table do
    if (table[i] == value) then
      return true
    end
  end
  return false
end



function mod.table_contains(table, element)
  for _, value in pairs(table) do
    if value == element then
      return true
    end
  end
  return false

end

-----------------------------------------------------------------------------
--[[ Function to extract the actual email from a pretty-print email address ]]--

function mod.esanitize(in_val)
  local sos = 1
  local eos = #in_val
  local out_val = in_val:sub(sos,eos)
  sos, eos = string.find(in_val, "<.*>", 1, false)
  if sos ~= nil and sos >= 1 then
    out_val = string.sub(in_val,sos+1,eos-1)
  end
  
  return (out_val)	
end

-----------------------------------------------------------------------------

-------- START Postmaster Alerts Function ------------------
function mod.postmaster_alert (alertsubject, notice)
  -- Assumes that the variable 'postmaster' was set above ( or fails)
  -- Assumes that the variable 'host_name' was set above ( or fails)
  if postmaster ~= nil and host_name ~= nil then
    local newmid = "Message-Id:<" .. tostring(kumo.uuid.new_v1(simple)) .. ">\r\n"
    local newdate = tostring(os.date("%a, %d %b %Y %X +0000")) .. "\r\n"
    local newtenant = "X-Tenant:InternalAlerts\r\n"
    local newcontenttype = "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
    local alertsender = "alerts@" .. host_name
    local newtext = newmid .. newdate .. newtenant .. newcontenttype .. "FROM:" .. alertsender .. "\r\nTO:" .. postmaster .. "\r\nSUBJECT:" .. alertsubject .. "\r\n\r\n" .. notice .."\r\n.\r\n"

    kumo.api.inject.inject_v1 {
      envelope_sender = alertsender,
      content = "This is a test",
      recipients = { { email = postmaster } },
    }
  end
end
-- This is included as an example:
-- postmaster_alert ("new mail"," a new mail has been injected")

-------- END Postmaster Alerts Function ------------------



function mod.splitdomain (domain_in)
  local t = {}
  t = kumo.string.split(domain_in, '.')
  return t
end


-- Count elements in a table
function mod.tablelength(T)
   local count = 0
   for _ in pairs(T) do count = count + 1 end
   return count
end



return mod
