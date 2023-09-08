--[[ *************************************** ]]--
--    INIT.LUA Tom's general version
--    Review and modify before use
--
--[[ *************************************** ]]--

local mod = {}
local kumo = require 'kumo'
local shaping = require 'policy-extras.shaping'

local shaper = shaping:setup_with_automation {
  publish = { 'http://127.0.0.1:8008' },
  subscribe = { 'http://127.0.0.1:8008' },
}

local utils = require 'policy-extras.policy_utils'

--[[ ================================================================================== ]]--
-- CALLED ON STARTUP, ALL ENTRIES WITHIN init REQUIRE A SERVER RESTART WHEN CHANGED.
kumo.on('init', function()

-- For debugging only
  kumo.set_diagnostic_log_filter 'kumod=debug'

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
    headers = { 'Subject', 'X-Customer-ID','Sender_local', 'X-Tenant' },
    meta = {'Sender_local','tenant','campaign','queue'},
--[[
  per_record = {
      Reception = {
        suffix = '_recv',
        enable = true,
      },
      Delivery ={
        suffix = '_deliv',
        enable = true,
      },
      TransientFailure = {
        suffix = '_trans',
        enable = true,
      },
      Bounce = {
        suffix = '_perm',
        enable = true,
      },
      Any = {
        suffix = '_any',
        enable = true,
      },
    },
  ]]--
  }

-- for webhooks

  kumo.configure_log_hook {
    name = 'webhook',
    headers = { 'Subject', 'X-Customer-ID','Sender_local', 'X-Tenant' },
    meta = {'Sender_local','tenant','campaign','queue'},
--[[
    per_record = {
      Reception = {
        suffix = '_recv',
        enable = true,
      },
      Delivery ={
        suffix = '_deliv',
        enable = true,
      },
      TransientFailure = {
        suffix = '_trans',
        enable = true,
      },
      Bounce = {
        suffix = '_perm',
        enable = true,
      },
      Any = {
        suffix = '_any',
        enable = true,
      },
    },
    ]]--
  }

  ]]--
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
    trusted_hosts = { '127.0.0.1', '::1', },
  }

        
                
-- for SMTP
local params = {
      listen = '0:25',
--      relay_hosts = {'127.0.0.1'},
      tls_private_key = "/opt/kumomta/etc/tls/my.demo.kumomta.com/privkey.pem",
      tls_certificate = "/opt/kumomta/etc/tls/my.demo.kumomta.com/cert.pem",
    }
   kumo.start_esmtp_listener(params)
        
    kumo.start_esmtp_listener {
      listen = '0:587',
  }


----------------------------------------------------------------------------
end) -- END OF THE INIT EVENT
----------------------------------------------------------------------------

--[[ ========================================================================== ]]--

cached_toml_load = kumo.memoize(kumo.toml_load,{name='cache-toml-files-for-1-hour', ttl='1 hour', capacity = 100,})
-- Get the domains configuration
    local listener_domains = require 'policy-extras.listener_domains'
    kumo.on('get_listener_domain', listener_domains:setup { '/opt/kumomta/etc/policy/listener_domains.toml' } )

-----------------------------------------------------
--[[ Define IP Egress Sources and Pools ]]--
-------------------------------------------------------
-- use the sources helper to configure IPs and Pools in one file
local sources = require 'policy-extras.sources'
sources:setup { '/opt/kumomta/etc/policy/egress_sources.toml' }


----------------------------------------------------------------------------
--[[ Traffic Shaping Helper ]]--
----------------------------------------------------------------------------
local shaping = require 'policy-extras.shaping'
local shaping_config = '/opt/kumomta/etc/policy/shaping.toml'
local get_shaping_config = shaping:setup()

kumo.on('get_egress_path_config', shaper.get_egress_path_config)


----------------------------------------------------------------------------
--[[ Configure Webhook feed ]]--
----------------------------------------------------------------------------
kumo.on('should_enqueue_log_record', function(msg,hook_name)
   if shaper.should_enqueue_log_record(msg, hook_name) then
     return true
   end

  local log_record = msg:get_meta 'log_record'
  -- avoid an infinite loop caused by logging that we logged that we logged...
  -- Check the log record: if the record was destined for the webhook queue
  -- then it was a record of the webhook delivery attempt and we must not
  -- log its outcome via the webhook.
  if log_record.queue ~= 'webhook' then
    -- was some other event that we want to log via the webhook
     msg:set_meta('queue', 'webhook')
    return true
  end
  return false
end)


-- This is a user-defined event that matches up to the custom_lua
-- constructor used in `get_queue_config` below.
-- It returns a lua connection object that can be used to "send"
-- messages to their destination.
kumo.on('make.webhook', function(domain, tenant, campaign)
--  local wh_target = 'http://webhooks.aasland.com:81/index.php'
  local wh_target = 'http://52.156.138.239:81/index.php'

  local connection = {}
  local client = kumo.http.build_client {}
  function connection:send(message)
    local response = client
      :post(wh_target)
      :header('Content-Type', 'application/json')
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

    -- Signal that the webhook request failed.
    -- In this case the 500 status prevents us from retrying
    -- the webhook call again, but you could be more sophisticated
    -- and analyze the disposition to determine if retrying it
    -- would be useful and generate a 400 status instead.
    -- In that case, the message we be retryed later, until
    -- it reached it expiration.
    kumo.reject(500, disposition)
  end
  return connection
end)


----------------------------------------------------------------------------
--[[ Determine queue routing ]]--
----------------------------------------------------------------------------
kumo.on('get_queue_config', function(domain, tenant, campaign)
  local tenant_list = cached_toml_load("/opt/kumomta/etc/policy/tenant_list.toml")
  local params = {
    egress_pool = tenant_list.TENANT_TO_POOL[tenant],
  }
  utils.merge_into(tenant_list.TENANT_PARAMS[tenant] or {}, params)

  local cfg = shaper.get_queue_config(domain, tenant, campaign)
  if cfg then
    return cfg
  end

  -- Routing for Webhooks delivery
    if domain == 'webhook' then
    return kumo.make_queue_config {
      protocol = {
        custom_lua = {
          constructor = 'make.webhook',
        },
      },
    }
  end

  return kumo.make_queue_config(params)
end)
----------------------------------------------------------------------------
--[[ DKIM Signing function ]]--
----------------------------------------------------------------------------
local dkim_sign = require 'policy-extras.dkim_sign'
local dkim_signer = dkim_sign:setup({'/opt/kumomta/etc/policy/dkim_data.toml'})

----------------------------------------------------------------------------
--[[ Determine what to do on SMTP message reception ]]--
----------------------------------------------------------------------------
kumo.on('smtp_server_message_received', function(msg)

-- added this to fix mesageID issues
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


  -- Assign tenant based on X-Tenant header.
 local tenant = msg:get_first_named_header_value('x-tenant') or 'default'

 msg:set_meta('tenant',tenant)
 msg:remove_x_headers { 'x-tenant' }

-- SIGNING MUST COME LAST OR YOU COULD BREAK YOUR DKIM SIGNATURES
  dkim_signer(msg)
end)

----------------------------------------------------------------------------
--[[ Determine what to do on HTTP message reception ]]--
----------------------------------------------------------------------------
kumo.on('http_message_generated', function(msg)
  -- Assign tenant based on X-Tenant header.
-- local tenant = msg:get_first_named_header_value('x-tenant') or 'default'
-- msg:set_meta('tenant',tenant)
  msg:set_meta('queue','null')

  msg:remove_x_headers { 'x-tenant' }


-- SIGNING MUST COME LAST OR YOU COULD BREAK YOUR DKIM SIGNATURES
  dkim_signer(msg)
end)

----------------------------------------------------------------------------
--[[ Adding basic Authentication (on disk) ]]--
----------------------------------------------------------------------------
-- FOR SMTP --
-- Use this to lookup and confirm a user/password credential
-- used with the http endpoint
kumo.on('smtp_server_auth_plain', function(authz, authc, password)
  local password_database = {
    ['tony'] = 'tiger',
  }
  if password == '' then
    return false
  end
  return password_database[authc] == password
end)

-- FOR HTTP --
-- Use this to lookup and confirm a user/password credential
-- used with the http endpoint
kumo.on('http_server_validate_auth_basic', function(user, password)
  local password_database = {
    ['tony'] = 'tiger',
  }
  if password == '' then
    return false
  end
  return password_database[user] == password
end)


----------------------------------------------------------------------------
--[[EOF]]--
-----------------------------------------------------------------------------
