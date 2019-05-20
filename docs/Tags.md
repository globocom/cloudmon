# CloudMon Tags

CloudMon checks and interprets resource tags that are present in VMs deployed within the region being monitored. Depending on the key/value defined by the tag CloudMon can take an specific monitoring action.

More info on resource tags: [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html) and [CloudStack](https://cwiki.apache.org/confluence/display/CLOUDSTACK/Resource+Tags)

CloudMon also provides a blacklist functionality to define with tags are allowed or not. See blacklisted in [Configuration](Configuration.md).

CloudMon tags are of two types: Default Tags and Custom Tags

## Default Tags
Default tags are of 5 types and each tag will represent a different action.

### monitoring
* `monitoring` tags will indicate if the VM will be monitored by CloudMon (CloudMon will create a corresponding zabbix host to the VM) or not.
* Accepts value 0 (not active) or 1 (active).
* Value 0 is interpreted the same way as non existent tag.
* Removal of one of those tags will delete its corresponding zabbix host.

### templates
* CloudMon will associate zabbix templates to the zabbix host that represents the monitored VM based on the information found at the `templates` tags.
* Works only in conjunction with an active monitoring tag.
* Accepts template names (one or serveral separated by comma) as values.
* Removal of one of those tags will desassociate the defined templates from the zabbix host.

### hostgroups
* CloudMon will associate zabbix hostgroups to the zabbix host that represents the monitored VM based on the information found at the `hostgroups` tags.
* Works only in conjunction with an active monitoring tag.
* Accepts hostgroup names (one or serveral separated by comma) as values.
* Removal of one of those tags will desassociate the defined hostgroups from the zabbix host.


### macros
* CloudMon will create zabbix macros in the zabbix host that represents the monitored VM based on the information found at the `macros` tags.
* Works only in conjunction with an active monitoring tag.
* Accepts pairs of key:value, (one or serveral separated by comma) as values.
* Example of usage: {$MACRO_1}:55, {$MACRO2}:https://cloudmon.readthedocs.io, '{$MACRO3}:hey, a comma'
* Removal of one of those tags will remove the defined macros from the zabbix host.

### zabbix_api
* CloudMon will do Zabbix API calls defined by this tag.
* Works only in conjunction with an active monitoring tag.
* Accepts multiple calls separated by semicolons.
* Example of usage: host.update({'hostid':'5', 'status':'0'}); host.update({'hostid':'6', 'status':'0'})
* The API call will be performed instantly by the cloudmon user defined in cloudmon.conf. Removal of one of  those tags doesn't do any actions
* Like the other tags, it's possible to predefine which calls are allowed or not to users with a blacklist. See blacklisted in [Configuration](Configuration.md).

More details of default tags at cloudstack_tags in [Configuration](Configuration.md).

## Custom Tags

* Custom tags are user created/defined tags and are defined in the cloudmon configuration files. See custom_tags in [Configuration](Configuration.md).
* A custom tag can perform several default tags actions at once as defined in its configuration. For example, with only one custom tag association is possible to create a zabbix host, associate it to predefined hostgroups and templates and create predefined macros.