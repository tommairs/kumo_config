# Current CS dev/test config

## Warning and Disclaimer
This is internal testing config only.  Shared for collaboration and debugging

The use of this config and anything in this repo is strictly voluntary and 
done at your own risk. 

If you choose to use this config you MUST modify it with your own values before attempting to use it. 

This is NOT a KumoMTA officialy supported config and is for experimental use only.  Feel free to copy 
and alter it to suit your needs.

~ Tom

## Usage
You should first have a vaild instal of KumoMTA.  Use this installer if you dont have one already built:
[https://github.com/tommairs/KumoMTAInstaller](https://github.com/tommairs/KumoMTAInstaller)

Clone this repo `git clone https://github.com/tommairs/kumo_config`

Make any required local edits (hostname, relay_hosts, etc)

Copy all files to /opt/kumomta/etc/policy/

Restart the KumoMTA service(s) `sudo systemctl restart kumomta.service kumo-tsa-daemon.service`
 
# Support
None whatsoever.  This is a private repo with no guarantee or support.

KumoMTA operational questions shoudl be directed to the [KumoMTA discord](https://discord.gg/grQBdm9h)

