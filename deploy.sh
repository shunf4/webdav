#!/bin/bash
source /etc/bashrc.d/03_sc_shortcut.sh
sc webdav stop
go build
sudo cp webdav /custom-apps/
sc webdav start
# px git push fengshun
