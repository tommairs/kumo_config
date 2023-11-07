local tsa = require 'tsa'
local kumo = require 'kumo'

kumo.on('tsa_init', function()
	kumo.set_diagnostic_log_filter 'tsa-kumo-daemon=debug'
  tsa.start_http_listener {
    listen = '0.0.0.0:8008',
    trusted_hosts = { '127.0.0.1', '::1' },
  }
end)

local cached_load_shaping_data = kumo.memoize(kumo.shaping.load, {
  name = 'tsa_load_shaping_data',
  ttl = '5 minutes',
  capacity = 4,
})

kumo.on('tsa_load_shaping_data', function()
  local shaping = cached_load_shaping_data {
    '/opt/kumomta/share/policy-extras/shaping.toml',
        -- and maybe you have your own rules
    '/opt/kumomta/etc/policy/shaping.toml',
  }
  return shaping
end)
