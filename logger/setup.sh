#!/bin/bash

OS=$(uname)
if [ "$OS" == "Linux" ]; then
	sudo apt-get install python-pip python-dev libssl-dev libffi-dev
fi

sudo -H pip install --upgrade pyopenssl
sudo -H pip install --upgrade oauth2client
sudo -H pip install --upgrade gspread
sudo -H pip install --upgrade dateutils
