bbfw
====

A simple way to manage iptables firewall configuration from the command line.

bbfw is not a complete firewall, is just a utility to make it easier to work with iptables and linux's netfilter.
bbfw allows you to:
- split netfilter configuration into simpler elements like tables and chains
- manage them as single individual files
- export the current configuration into bbfw's own internal format
- show and load bbfw internal format into netfilter

bbfw commands
-------------
- export creates a new configuration from the running netfilter
- show displays the a netfilter configuration, either current or from a config folder or file
- load loads bbfw configuration into netfilter
- compare compares bbfw's configuration with netfilter
- purge remove chains or tables from netfilter configuration


In a nutshell
-------------
1. `bbfwmgr show` displays the current netfilter configuration
2. `bbfwmgr export` creates a folder in the current directory containing bbfw config, exported from the running netfilter configuration
3.  now manually edit the rules in the newly created "tables" folder, using a text editor
4. `bbfwmgr compare` compares bbfw configuration with the live netfilter one
5. `bbfwmgr load` loads the bbfw configuration into netfilter

Once you have a bbfw configurqtion created, you can edit the tables, chains and ruls using a text editor.
Rules are written using netfilter's `iptables` command syntax, one command per line; you don't need the append/insert and the table/chain name (e.g. no "-A INPUT" prefix).

