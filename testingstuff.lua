-------------------------------------------------
-- A collection of functions here mainly for testing
--  and samples.  Add new functions to the bottom
------------------------------------------------

local kumo = require("kumo")

-- Available Parallelism
print ("Available parallelism = ", kumo.available_parallelism())


-- Glob function
-- logs the names of all of the '*.conf' files under `/etc`
print("This is a glob of all .conf files in /etc")
print(kumo.json_encode_pretty(kumo.glob '/etc/*.conf'))


-- JSON Encode
local testvalue = "MyValue = 42"
print ("JSON encoded version of " .. testvalue .. " is " .. kumo.serde.json_encode(testvalue))


-- read_dir
-- Shows all files in /opt/kumomta/etc/policy
print ("This a file listing of the policy directory:")
print(kumo.json_encode_pretty(kumo.read_dir '/opt/kumomta/etc/policy/'))




