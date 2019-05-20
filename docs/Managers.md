# Manager

Managers are simply zabbix hosts in which you will define the parameters of the cloud region you want to monitor.

Once a manager is properly configured and active no further action is required in Zabbix and CloudMon will automatically create/remove/update zabbix hosts according to the events of the Cloud.

CloudMon supports several managers simultaneously.

## Creating and Configuring a manager

* Copy the file push_message.py to your zabbix external scripts dir and make sure it has the proper exec permissions.
* Import the zabbix template "Template CloudMon Instances" found in the file template_cloudmon.xml.
* Create a new zabbix host and associate it to this template. Configure an agent interface pointing to CloudMon's IP address and its agent port (127.0.0.1 in cases which CloudMon is installed in the zabbix server or proxy).
* Associate the new host to the desired hostgroups.
* Create Zabbix Macros to configure your monitoring parameters as indicated in [Macros](Macros.md).
* Edit the frequency of the monitoring loops (Item of Template CloudMon Instances)
* Enable the host