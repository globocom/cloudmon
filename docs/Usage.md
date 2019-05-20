# Usage

After installation you should be able to start cloudmon either directly with the cloudmon command or by initializing its initd daemon.

```
usage: cloudmon [-h] [-c CONFIG] [-p PID] [-v] [-l] [-f]

CloudMon is a monitoring orchestrator for clouds.

optional arguments:
  -h, --help            Show this help message and exit
  -c CONFIG, --config CONFIG
                        Path of the config file
  -p PID, --pid PID     Path of the pid file
  -v, --version         Show CloudMon version
  -l, --log-stdout      Logs will be send to stdout instead of stored in files
  -f, --foreground      Run proccess in foreground
```

