# CloudMon


CloudMon is a monitoring orchestrator for clouds. Cloudmon integrates directly an IaaS plataform (currently works with Apache CloudStack and AWS EC2) with a monitoring plataform (Zabbix).


On the fly, CloudMon will:

* create, delete or change status of zabbix hosts (each host corresponds to an IaaS VM) and even update its configurations (templates, hostgroups, macros...) replicating the changes (created/removed/stopped) ocurred within the VMs.

* Read VMs [resource tags](Tags.md) and take different actions based on its values.

* Associate zabbix hosts to predefined templates or hostgroups.

* Simultaneously monitor multiple Cloud regions (different or same IaaS).

CloudMon works as a Python Daemon that retrieves IaaS data through CloudStack API, AWS EC2 API and/or its event queues, processing that data and taking the proper action in Zabbix through the Zabbix API.

CloudMon requires a Zabbix Agent installed to ensure proper functionality.

CloudMon has been tested and used in CentOS environments and Python 2.7.




## Getting Started

* Read the [documentation](https://cloudmon.readthedocs.io)
* Recommended to create a python virtualenv for CloudMon.
* Install via `pip install cloudmon`.
* Edit your `cloudmon.conf` file for your needs. See [Configuration](Configuration.md).
* Create and edit one or more [managers](Managers.md).
* Edit /etc/init.d/cloudmon if needed.
* Run CloudMon with: `cloudmon` or `/etc/init.d/cloudmon start | stop | restart`. See [Usage](Usage.md).

## Success Stories

CloudMon has been successfully used by Globo.com to monitor its Cloud Infrastructure.