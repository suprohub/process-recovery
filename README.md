# process-recovery
An IDA plugin for recovering process info via debuginfod.

Instruction:
1. Download file and copy it in /opt/ida-pro/loaders/
2. Start process and get pid.
3. Open in ida file named /proc/<pid>/mem (you maybe need run ida in sudo, and if process have gui when maybe with this command: `sudo -E -u root DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY ida`)
4. Set process bitness
5. Skip some wanings and errors.
6. Done
