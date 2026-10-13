# RemoteOps - Remote System Monitoring Tool

**Student:** IT24102550
**Module:** IE3090 - Network Programming

## Personalised Values
- **Agent Port:** 9410
- **SID:** 552
- **Auth Token:** OPS-2550
- **Log File:** remoteops_IT24102550.log
- **Storage Path:** ./agentfiles/IT24102550/

## Build
make -f Makefile_550

## Run
./agent_550
./controller_550

## Features
- AUTH authentication
- SYSINFO (CPU, memory, uptime)
- LISTPROC (process list)
- EXEC (whitelisted: DATE, UPTIME, DISKFREE, HOSTNAME, WHOAMI)
- PUT/GET (file transfer)
- LIST (list stored files with count, names, and sizes in personalised path)
- Multiple clients (threads)
- UDP monitoring (MONITOR START/STOP)
- Logging
## Commit History
This repository contains 8+ meaningful commits documenting the development process:
1. Initial commit
2. Complete implementation (AUTH, SYSINFO, LISTPROC, EXEC, PUT/GET, threads, UDP, logging)
3. Detailed README
4. Design diary
5. AI prompt log
6. Structured reflection
7. Updated .gitignore
8. README commit history

## License
Academic submission - IE3090 Network Programming, SLIIT
