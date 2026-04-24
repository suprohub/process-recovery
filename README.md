# process-recovery
An IDA plugin for recovering process info via debuginfod.

Instruction:
1. Start process and get pid.
2. Open in ida file named /proc/<pid>/mem (you maybe need run ida in sudo, and if process have gui when maybe with this command: `sudo -E -u root DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY ida`)
3. Set process bitness
4. Skip some wanings and errors.
5. Done
