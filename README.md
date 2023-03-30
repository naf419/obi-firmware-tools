# obi-firmware-tools

Here lies an attempt to document the firmware format for obi100/110 ATAs, obi200/202/302 ATAs, obi1022/1032/1062 ip phones, obi504/508 ATAs, and obid230 DECT phones and provide tools to manipulate the contents.

obi added x509 certificate checks to the firmware upgrade routine of stock firmware (5853+ for ATAs and 5-1-11-4858+ for phones), making it more difficult to upgrade to a custom firmware. Luckily their initial implementation contained a flaw that allowed the certificate to be bypassed. That flaw has been fixed, but is still available to use via a simple downgrade to an older vulnerable version.
