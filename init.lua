--[[ *************************************** ]]--
--    INIT.LUA Tom's version
--[[ *************************************** ]]--
--
-- This top section before the init phase is critical to preload
-- libraries that will be required in the init phase
--
local mod = {}
local kumo = require 'kumo'

-- Load helper and utility librariess
local utils = require 'policy-extras.policy_utils'
local k_helpers = require 'k_helpers'
local sqlite = require 'sqlite'

local shaping = require 'policy-extras.shaping'
local log_hooks = require 'policy-extras.log_hooks'
local queue_module = require 'policy-extras.queue'
local listener_domains = require 'policy-extras.listener_domains'
local sources = require 'policy-extras.sources'
local dkim_sign = require 'policy-extras.dkim_sign'


-- Create first basic webhook
local wh_target = 'http://demo.kumomta.com:80//collector/'
k_helpers.create_webhook("webhook",wh_target,"a_ebhook_user","a_webhook_password",log_hooks)


-- Create second alternate webhook
--[[ commented as this is only an example
local wh_target = 'http://collectors.kumomta.com:81/hud2/collect/'
local basic_wh = create_webhook("webhook2",wh_target,"fakeusername","A.ReallyBadPassword",log_hooks)
]]--


-- Load TSA shaper tools
local shaping_config = '/opt/kumomta/etc/policy/shaping.toml'
  local shaper = shaping:setup_with_automation {
  publish = { 'http://127.0.0.1:8008' },
  subscribe = { 'http://127.0.0.1:8008' },
  extra_files = {shaping_config},
}

--[[ ================================================================================== ]]--
-- INIT phase
-- CALLED ON STARTUP, ALL ENTRIES WITHIN init REQUIRE A SERVER RESTART WHEN CHANGED.
--[[ ================================================================================== ]]--

kumo.on('init', function()

-- For debugging only
--  kumo.set_diagnostic_log_filter 'kumod=debug,kumod::queue=trace'
--  kumo.set_diagnostic_log_filter 'kumod=debug'

-----------------------------------------------------
--[[ Define the Spool ]]--
-----------------------------------------------------
  kumo.define_spool {
    name = 'data',
    path = '/var/spool/kumomta/data',
    kind = 'RocksDB',
  }

  kumo.define_spool {
    name = 'meta',
    path = '/var/spool/kumomta/meta',
    kind = 'RocksDB',
  }
-----------------------------------------------------
--[[ Define logging parameters ]]--
-----------------------------------------------------
-- Configure publishing of TSA logs to automation daemon
  shaper.setup_publish()


-- for local logs
  kumo.configure_local_logs {
    log_dir = '/var/log/kumomta',
    max_segment_duration = '5 minutes',
  }

-----------------------------------------------------
--[[ Configure Bounce Classifier ]]--
-----------------------------------------------------
  kumo.configure_bounce_classifier {
    files = {
      '/opt/kumomta/share/bounce_classifier/iana.toml',
    },
  }

-----------------------------------------------------
--[[ Configure listeners ]]--
-----------------------------------------------------

--for HTTP(s)
  kumo.start_http_listener {
    listen = '0.0.0.0:8000',
    -- allowed to access any http endpoint without additional auth
    trusted_hosts = { '127.0.0.1', '::1' },
  }

                
-- for SMTP
local params = {
      listen = '0:25',
      relay_hosts = {'127.0.0.1'},
    --  banner = "My email server",
    --  tls_private_key = "/opt/kumomta/etc/tls/my.demo.kumomta.com/ca.key",
    --  tls_certificate = "/opt/kumomta/etc/tls/my.demo.kumomta.com/ca.crt",
    }
   kumo.start_esmtp_listener(params)
    
   -- apply the same params to port 587
  local params = {
      listen = '0:587',
  }
   kumo.start_esmtp_listener(params)


----------------------------------------------------------------------------
end) -- END OF THE INIT EVENT
----------------------------------------------------------------------------


--[[ ======= Load Helpers ============================ ]]--

-- Load  Queue helper 
-- You can pass multiple file names if desired
 local queue_helper = queue_module:setup({'/opt/kumomta/etc/policy/queues.toml'})

-- Load Listener Domains Helper
kumo.on('get_listener_domain', listener_domains:setup { '/opt/kumomta/etc/policy/listener_domains.toml' } )

-- Load Egress Sources and Pools Helper 
sources:setup { '/opt/kumomta/etc/policy/egress_sources.toml' }


-- Load  Traffic Shaping Helper 
local get_shaping_config = shaping:setup()
kumo.on('get_egress_path_config', shaper.get_egress_path_config)


-- Load DKIM Signing helper function
local dkim_signer = dkim_sign:setup({'/opt/kumomta/etc/policy/dkim_data.toml'})


----------------------------------------------------------------------------
--[[ Determine queue routing ]]--
----------------------------------------------------------------------------
--[[ Note that this section is ignored if you use the queue helper
kumo.on('get_queue_config', function(domain, tenant, campaign)
-- This is here in case you want to add any custom queue config

print ("domain,tenant,campaign")
print (domain,tenant,campaign)


  if domain == 'gmail.com' then
    -- Store this domain into a maildir, rather than attempting
    -- to deliver via SMTP
    return kumo.make_queue_config {
      protocol = {
        maildir_path = '/var/tmp/kumo-maildir',
      },
    }
  end
  -- Otherwise, just use the defaults

  return kumo.make_queue_config{}
end)
]]--


----------------------------------------------------------------------------
--[[ Determine what to do on SMTP message reception ]]--
----------------------------------------------------------------------------
kumo.on('smtp_server_message_received', function(msg)

-----------------------------------------
  -- Added this to fix messageID issues
  -- This shoudl always be loaded first
  local failed = msg:check_fix_conformance(
    -- check for and reject messages with these issues:
    'MISSING_COLON_VALUE',
    -- fix messages with these issues:
    'LINE_TOO_LONG|NAME_ENDS_WITH_SPACE|NEEDS_TRANSFER_ENCODING|NON_CANONICAL_LINE_ENDINGS|MISSING_DATE_HEADER|MISSING_MESSAGE_ID_HEADER|MISSING_MIME_VERSION'
  )
  if failed then
    kumo.reject(552, string.format('5.6.0 %s', failed))
  end
-----------------------------------------

  queue_helper:apply(msg)

--[[ Sample code to add list-unsubscribe headers in-transit
    local keyuserid = k_helpers.to_base64(msg:recipient().email .. msg:get_meta('tenant'))
    msg:append_header("List-Unsubscribe", "<mailto:unsub@demo2.kumomta.com?subject=unsub>, <https://luna.kumomta.com/unsubscribe.php?t=" .. keyuserid .. ">")
    msg:append_header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
]]--


print ("DKIM signing message")
-- SIGNING MUST COME LAST OR YOU COULD BREAK YOUR DKIM SIGNATURES
  dkim_signer(msg)
end)



----------------------------------------------------------------------------
--[[ Determine what to do on HTTP message reception ]]--
----------------------------------------------------------------------------
kumo.on('http_message_generated', function(msg)

  queue_helper:apply(msg)

-- SIGNING MUST COME LAST OR YOU COULD BREAK YOUR DKIM SIGNATURES
  dkim_signer(msg)
end)



----------------------------------------------------------------------------
--[[ Adding basic Authentication (on disk) ]]--
----------------------------------------------------------------------------

function sqlite_auth_check(user, password)
  local db = sqlite.open '/home/myaccount/mypswd.db'
  local result = db:execute ('select * from users where email=? and password=?', user ,password)

  -- if we return the username, it is because the password matched
  return result[1] == user
end

-- Cache the credentials so we are not constantly hitting the DB
cached_sqlite_auth_check = kumo.memoize(sqlite_auth_check, {
  name = 'sqlite_auth',
  ttl = '5 minutes',
  capacity = 100,
})



--------------------------------------------------------------------------------
-- Use this to lookup and confirm a user/password credential with the HTTP event
kumo.on('http_server_validate_auth_basic', function(user, password)

  return cached_sqlite_auth_check(user, password)
end)


--------------------------------------------------------------------------------
-- Use this to lookup and confirm a user/password credential with the SMTP event
kumo.on('smtp_server_auth_plain', function(authz, authc, password)

  return cached_sqlite_auth_check(authc, password)
end)
----------------------------------------------------------------------------
--[[EOF]]--
-----------------------------------------------------------------------------
