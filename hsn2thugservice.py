#!/usr/bin/python -tt

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

'''
Created on 30-05-2012

@author: wojciechm
'''

import sys
sys.path.append("/opt/hsn2/python/commlib")
from hsn2service import HSN2Service
from hsn2thugtaskprocessor import ThugTaskProcessor
from hsn2service import startService
from os import access
from os import path
import logging

class ThugService(HSN2Service):
	'''
	This is the HSN2 service which utilizes the Thug Python low-interaction honeyclient.
	'''
	serviceName = "thug"
	description = "HSN 2 Thug Service"

	def extraOptions(self,parser):
		'''Arguments specific to this service. Receives a parser with the standard options. Returns a modified parser.'''
		parser.add_argument('--thug', '-t', action='store', help='path to the thug.py file', default="/opt/hsn2/thug/src/thug.py", required=False, dest='thug')
		return parser

	def sanityChecks(self, cliargs):
		passed = HSN2Service.sanityChecks(self, cliargs)
		if not path.isfile(cliargs.thug):
			logging.error("'%s' is not a file" % cliargs.thug)
			passed = False
		return passed

if __name__ == '__main__':
	startService(ThugService,ThugTaskProcessor)