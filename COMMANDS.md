# HoneyFTP Command Reference

This document lists the main commands you can try against the honeypot using
`attacker_shell.py` or any FTP client.

## FTP commands

| Command | Description |
|---------|-------------|
| `connect <host> <port> [user] [password]` | Establish the FTPS connection (sends the knock sequence automatically). |
| `login [user] [password]` | Authenticate after connecting. |
| `close` | Terminate the FTP session. |
| `ls [dir]` | List files in the current or given directory. |
| `cd <dir>` | Change directory. |
| `pwd` | Print the current remote directory. |
| `get <file> [dest]` | Download a file. |
| `put <local_file> [remote]` | Upload a file. |
| `mkdir <dir>` | Create a directory on the server. |
| `rmdir <dir>` | Remove a directory. |
| `cat <file>` | Display a text file. |
| `grep <pattern> <file>` | Search for a pattern inside a remote text file. |
| `site <subcommand>` | Send a SITE command (e.g. `SITE HELP`). |
| `raw <cmd>` | Send any raw FTP command. |
| `quit` | Exit the interactive client. |

The honeypot also supports standard FTP features such as `RNFR/RNTO`, `DELE`,
`STAT`, `MODE`, and `SIZE`. When using another FTP client (FileZilla, etc.) you
can perform regular operations like uploading or renaming files. Some commands
are simulated: `SITE EXEC` or `SITE SHELL` only return fake responses and do not
execute real commands.

See `attaque.md` for a step-by-step scenario using `attaquant.py`.
