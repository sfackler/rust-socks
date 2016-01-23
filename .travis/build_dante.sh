#!/bin/bash
set -e

cd $HOME
curl https://www.inet.no/dante/files/dante-1.4.1.tar.gz | tar xzf -
cd dante-1.4.1
./configure --prefix $HOME/dante
make install -j4
