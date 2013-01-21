#!/bin/sh

# Copyright (c) NASK
# 
# This file is part of HoneySpider Network 2.0.
# 
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This installation script is currently only meant for systems which have the apt-get tool.

apt-get install automake autoconf libtool python-bs4 python-setuptools build-essential git-core subversion scons python-chardet python-html5lib libboost-python-dev libboost-dev python-pefile python-httplib2

cd /tmp
git clone git://git.carnivore.it/libemu.git
cd libemu
autoreconf -v -i
./configure --prefix=/opt/libemu
make install

cd /tmp
git clone https://github.com/buffer/pylibemu
cd pylibemu
python setup.py build
python setup.py install

cd /opt/hsn2/thug
git clone https://github.com/buffer/thug.git
cd ./thug/
svn checkout http://v8.googlecode.com/svn/trunk/ v8
cp patches/V8-patch* .
patch -p0 < V8-patch1.diff
patch -p0 < V8-patch2.diff
rm V8-patch*
cd /tmp/
svn checkout http://pyv8.googlecode.com/svn/trunk/ pyv8
export V8_HOME=/opt/hsn2/thug/thug/v8
cd pyv8 && python setup.py build
python setup.py install
mv /opt/hsn2/thug/thug/* /opt/hsn2/thug/
rm -r /opt/hsn2/thug/thug
cd /opt/hsn2/thug/src
python thug.py
