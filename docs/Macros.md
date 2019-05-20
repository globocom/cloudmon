# Zabbix Macros
Here is a list of all zabbix macros that are accepted by the [manager hosts](Managers.md). Multiple values should be separated with commas.

#### {$KEY}
* API key for the Apache CloudStack API or access key ID for the AWS API.

#### {$SECRET}
* Secret key for the Apache CloudStack API or secret access key for the AWS API.

#### {$URL}
* Endpoint for the Apache CloudStack API or AWS API.

#### {$REGION}
* Region parameter for the AWS API.

#### {$MONITOR_OPERATIONS}
* Operations that will be done by the APIs  ([create, update, delete] choose one or more).

#### {$VM_GROUPS}
* Hostgroups (names) that will be automatically associated with the newly created hosts of VM kind.

#### {$VM_TEMPLATES}
* Templates (names) that will be automatically associated with the newly created hosts of VM kind

#### {$ROUTER_GROUPS}
* Hostgroups (names) that will be automatically associated with the newly created VM hosts of Virtual Router kind.

#### {$ROUTER_TEMPLATES}
* Templates (names) that will be automatically associated with the newly created hosts of Virtual Router kind

#### {$SYSTEM_VM_GROUPS}
* Hostgroups (names) that will be automatically associated with the newly created hosts of System VM kind.

#### {$SYSTEM_VM_TEMPLATES}
* Templates (names) that will be automatically associated with the newly created hosts of System VM kind.

#### {$AGGREGATE_TEMPLATE}
* Template to generate an aggregated host with data of VMs from a same project.

#### {$EXTRA_GROUPS_STR}
* Prefix that will be concatenated before every hostgroup (name) associated through tags of "hostgroups" kind.

#### {$EXTRA_TEMPLATES_STR}
* Prefix that will be concatenated before every template (name) associated through tags of "templates" kind.

#### {$EXTRA_MACROS_STR}
* Prefix that will be concatenated before every macro (name) associated through tags of "macros" kind.

#### {$EXTRA_CLASS_STR}
* Prefix that will be concatenated before every API class called through tags of "zabbix_api" kind.

#### {$EXTRA_METHOD_STR}
* Prefix that will be concatenated before every API method  called through tags of "zabbix_api" kind.

#### {$USERGROUPS}
* Usergroups (name) described here will associated to the newly created hostgroups.

#### {$QUEUE_URL}
* URL parameter for the AMQP queue.

#### {$QUEUE_QUEUE}
* Queue parameter for the AMQP queue

#### {$QUEUE_EXCHANGE}
* Exchange parameter for the AMQP queue.