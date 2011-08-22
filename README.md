A fuse filesystem for managing iptables
=======================================
I usually configure my system by editing files in `/etc`, `/proc` or `/sys`.
But I can't configure my firewall like that, since it exposes no configuration filesystem.
So I've decided to write my own. However, I didn't stop at merely exposing a primitive interface.
I have made it actually useful, and easier to use than plain iptables.

Installation
------------

    # pip install fuse-python
    # cp iptablesfs.conf.py /etc

Usage
-----

    # mkdir ipt
    # python2 iptables.py ipt

Note that you might have `python2` installed as `python`, `python2.7` or somehing else. But you know your system, right?

Now, since you have successfully mounted the filesystem, how to use it.

  * The main directories are tables. You can't do anything with them, except entering them.
  * In each table, there are chains. You can create them using `mkdir`, delete them using `rmdir`, etc.. You can't remove built-in chains, of course.
  * In each chain, there are usually multiple files. They are your filters. They are fully configurable, but you can't create or delete them using your shell commands.
  * If you overwrite a filter file, like `tcp`, only the rules in that file will be deleted, as expected.

An example:

    # cd filter/INPUT
    # ls
    ACCEPT DROP policy REJECT rules tcp udp
    # cat rules
    # echo --dport 123 -j ACCEPT > udp
    # cat rules
    -p udp -m udp --dport 123 -j ACCEPT
    # echo --dport 321 -j DROP > tcp
    # echo --dport 42 -j ACCEPT >> tcp
    # cat rules
    -p udp -m udp --dport 123 -j ACCEPT
    -p tcp -m tcp --dport 321 -j DROP
    -p tcp -m tcp --dport 42 -j ACCEPT
    # cat DROP
    -p tcp -m tcp --dport 321
    # cat tcp
    --dport 321 -j DROP
    --dport 42 -j ACCEPT
    # echo --dport 23 -j ACCEPT > tcp
    # cat rules
    -p udp -m udp --dport 123 -j ACCEPT
    -p tcp -m tcp --dport 23 -j ACCEPT

Configuration
-------------
The whole configuration is a dictionary of files. Each file is a filter for `iptables -t table -S chain`.

The keys are file names, and the values are dictionares containing following properties (all optional):

  * `match`: regular expression, lines that match it will be visible in this file. opposite of exclude
  * `exclude`: regular expression, lines that match it will not be further processed, and won't be visible in this file
  * `hide`: array of regular expressions, parts of line that match them will not be displayed in the file
  * `exists`: a lamda taking parameters fs, table, chain. decides whether the file exists in this chain. true by default
  * `chain_option`: command that will be used when adding lines. -A (append) by default.
  * `prepend`: a string to prepend to the line, when adding it to the file.
  * `append`: a string to append to the line, when adding it to the file.

The `fs` object in lambdas is the Filesystem class. The only interesting member of this class is `chains`. See the default configuration for an example on how it's intended to be used.

Any suggestions, comments, and especially useful filters are appreciated.
