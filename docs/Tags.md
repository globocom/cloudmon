# CloudMon Tags

CloudMon checks and interprets resource tags that are present in virtual machines deployed in the region being monitored.

CloudMon tags are of two types: Default Tags and Custom Tags

## Default Tags
Default tags are of 5 types: monitoring, templates, hostgroups, macros and zabbix_api
#### monitoring
-
#### templates
-
#### hostgroups
-
#### macros
-
#### zabbix_api
* A tag zabbix_api envia chamadas para a API do Zabbix
* Saídas dos comandos executados via tags zabbix_api podem ser logadas em arquivo separado. Definido na config do CloudMon, ver model.conf, seção [logging]
* Múltiplas chamadas são aceitas em uma mesma tag, separadas por ';' (call1; call2; call3;). Múltiplas chamadas são executadas na ordem que foram enviadas
* Chamadas são compostas por class, method e params (class.method(params))
* Formato das chamadas: zabbix_api = class1.method1(params1); class2.method2(params2);
* Ex:
```
zabbix_api = host.update({'hostid':'5', 'status':'0'}); usermacro.create({'hostid':'5', 'macro':'{$MACR}', 'value':'foo'});
```

##### Variáveis
* Em chamadas zabbix_api as respectivas variáveis são aceitas e armazenam a referida informação da vm:
      * $\_name\_
      * $\_ip0\_($\_ip1\_, etc... quantos existirem)
      * $\_vlan0\_ ($\_vlan1\_, etc... quantos existirem, respectivas ao ip)
      * $\_zonename\_
      * $\_project\_
* As variáveis devem ser passadas como string, entre aspas, como demais valores da tag zabbix_api
* Exemplo: ```host.get({'host':'$_name_'})```
* É possível concatenar variáveis entre si ou a outros valores string. Ex: ```host.get({'host':'$_name_-$_ip0_'})``` envia ```host.get({'host':'nome_da_vm-192.168.4.5'})```
* O CloudMon suporta variáveis apenas no primeiro nível dos dicts ou lists. Ex:` param = {'a':'1nivel', 'b':'1nivel', 'c':{'a':'2nivel'}}`
* Vars em níveis seguintes não são interpretadas

-
#### Blacklist e extra string
* Todos os tipos de regular tags suportam blacklist e extra string. Ver aquivo [model.conf](model.conf) e [macros.MD](macros.MD) para maiores detalhes



## Custom Tags
- To do


