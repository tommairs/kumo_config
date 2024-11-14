local kumo = require("kumo")

local webhook_domain = 'webhook.dev'
local webhook_url = "http://utils.kumomta.com/whc/index.php"

kumo.on("pre_init", function()
	print ("Creating Webhook definition")
	kumo.configure_log_hook({
			name = webhook_domain,
			headers = {
				"Subject",
				"X-Customer-ID",
				"x-virtual-mta",
				"x-customer-id",
				"x-leid",
				"x-job",
				"x-account",
				"x-instance",
			},
			meta = {
				"tenant",
				"x_virtual_mta",
				"x_customer_id",
				"x_leid",
				"x_job",
				"x_account",
				"x_instance",
				"x_route_type",
				"received_from",
				"send_host",
				"orcpt",
				"x_envid",
			},
		})
	end)

	kumo.on("should_enqueue_log_record", function(msg, hook_name)
		local log_record = msg:get_meta("log_record")
		-- avoid an infinite loop caused by logging that we logged that we logged...
		if log_record.reception_protocol == "LogRecord" then
			return false
		end
		print("Enquing webhook to", hook_name)

                msg:set_meta("queue", webhook_domain)
                return true
	end)


	kumo.on("get_queue_config", function(domain, tenant, campaign, routing_domain)
		if domain ~= webhook_domain then
			return
		end
		print ("Creating Lua Constructor")
		return kumo.make_queue_config({
			retry_interval = "30s",
			max_retry_interval = "5m",
			max_message_rate = "10000/m",
			protocol = {
				custom_lua = {
					batch_size = 1000,
					constructor = "make.webhook.custom",
				},
			},
		})
	end)


kumo.on("make.webhook.custom", function(webhook_domain, webhook_tenant, webhook_campaign)
	local connection = {}
	local target_url = webhook_url
	local client = kumo.http.build_client({})
print ("Firing custom webhook process")
	-- This method must be named send_batch when batch_size > 1
	function connection:send_batch(messages)
		local status, error_or_disposition = pcall(function()
			local payload = {}
			for _, msg in ipairs(messages) do
				local element = prepare_batch_element(msg)
				table.insert(payload, kumo.serde.json_encode(element))
			end

			if #payload == 0 then
				-- filtered out all messages from this batch.
				return "250 all messages filtered"
			end
			print ("Adding log payload")
			local data = table.concat(payload, "\n")
			print("POST'ing hook to URL")
			local response = client:post(target_url):header("Content-Type", "application/json"):body(data):send()
			local disposition =
				string.format("%d %s: %s", response:status_code(), response:status_reason(), response:text())
			if response:status_is_success() then
				print(
					os.date("%Y/%m/%d %H:%M:%S"),
					"Successful webhook batch of " .. #payload .. " sent to " .. webhook_domain
				)
				print(os.date("%Y/%m/%d %H:%M:%S"), "250 HTTP status " .. disposition)
				return "250 HTTP status " .. disposition
			end
			print(os.date("%Y/%m/%d %H:%M:%S"), "Webhook batch of " .. #payload .. " FAILED  to " .. webhook_domain)
			print(os.date("%Y/%m/%d %H:%M:%S"), "450 HTTP status " .. disposition)
			return "450 HTTP status " .. disposition
		end)

		-- Set Webhook shipping throttle.  
		-- a throttle of 1/minute will pause webhook shipping for 1 minute while it fills
                --[[
		local throttle = kumo.make_throttle(
                  string.format('batch-send-rate-for-%s', webhook_domain),
                  '1/minute'
                ) 
                throttle:sleep_if_throttled()
		]]--
                --------------------------------------


		if not status then
			print(
				os.date("%Y/%m/%d %H:%M:%S"),
				"Error processing batch of " .. #messages .. ": " .. tostring(error_or_disposition)
			)
			return "450 " .. tostring(error_or_disposition)
		end

		return error_or_disposition
	end

	function connection:close()
		client:close()
	end

	return connection
end)


function prepare_batch_element(msg)

	-- build payload
	print(os.date("%Y/%m/%d %H:%M:%S"), "Preparing log for webhook")
	--
	-- Get PMTA style event type
	local log_record = msg:get_meta("log_record")
        local result = log_record 
	return result

end

