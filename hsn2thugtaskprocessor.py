

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
from hsn2objectwrapper import BadValueException
sys.path.append("/opt/hsn2/python/commlib")
from hsn2taskprocessor import HSN2TaskProcessor
from hsn2taskprocessor import ParamException, ProcessingException
from hsn2osadapter import ObjectStoreException
import hsn2objectwrapper as ow
import logging
import subprocess
from hsn2thuganalysisparser import ThugAnalysisParser
import os
import shutil
import time
import tempfile
import re

ANALYSIS_DIR_REGEXP = re.compile(r"Saving log analysis at\s([\.a-z0-9/]+)")

class ThugTaskProcessor(HSN2TaskProcessor):
	'''
	Task processor for Thug.
	What should be done in processing:
	1) launch appropriate Thug methods with required arguments
	2) read output - determine whether successful or failed
	3a) If failed throw TaskFailedException
	3b) If successful return tuple (task, warnings)
	'''
	thug = None
	thugDir = None
	parser = None

	def __init__(self,connector,datastore,serviceName,serviceQueue,objectStoreQueue,**extra):
		'''
		Runs Process init first and then creates required connections.
		'''
		HSN2TaskProcessor.__init__(self,connector,datastore,serviceName,serviceQueue,objectStoreQueue,**extra)
		self.thug = extra.get("thug")
		self.thugDir = os.path.split(self.thug)[0]
		self.parser = ThugAnalysisParser()

	def taskProcess(self):
		'''	This method should be overridden with what is to be performed.
			Returns a list of warnings (warnings). The current task is available at self.currentTask'''
		logging.debug(self.__class__)
		logging.debug(self.currentTask)
		logging.debug(self.objects)
		if len(self.objects) == 0:
			raise ObjectStoreException("Task processing didn't find task object.")

		referer = ""

		if self.objects[0].isSet("url_original"):
			url = self.objects[0].url_original
		elif self.objects[0].isSet("url_normalized"):
			url = self.objects[0].url_normalized
		else:
			raise ParamException("Both url_original and url_normalized are missing.")
		if self.objects[0].isSet("referer"):
			referer = "--referer=%s" % self.objects[0].referer

		useragent = ""
		proxy = ""
		verbose = "--verbose"
		debug = ""
		save_zip = False
		save_js_context = True

		try:
			for param in self.currentTask.parameters:
				if param.name == "useragent":
					value = str(param.value)
					if len(value) > 0:
						useragent = "--useragent=%s" % value
				elif param.name == "proxy":
					value = str(param.value)
					if len(value) > 0:
						proxy = "--proxy=%s" % value
				elif param.name == "verbose":
					verbose = self.paramToBool(param)
					if verbose:
						verbose = "--verbose"
					else: verbose = ""
				elif param.name == "debug":
					debug = self.paramToBool(param)
					if debug:
						debug = "--debug"
					else: debug = ""
				elif param.name == "save_zip":
					save_zip = self.paramToBool(param)
				elif param.name == "save_js_context":
					save_js_context = self.paramToBool(param)
		except BaseException as e:
			raise ParamException("%s" % str(e))

		args = ["python", self.thug, useragent, proxy, verbose, debug, referer, url]
		args = [x for x in args if len(x) > 0]

		self.objects[0].addTime("thug_time_start",int(time.time() * 1000))
		output = self.runExternal(args)
		self.objects[0].addTime("thug_time_stop",int(time.time() * 1000))
		if output[0] is not None:
			match = ANALYSIS_DIR_REGEXP.search(output[0])
			if match:
				relativeLogDir = match.group(1)
			else:
				self.objects[0].addBool("thug_active", False)
				self.objects[0].addString("thug_error_message", "Couldn't find log dir in output: " + repr(output[0]))
				return []
			
			logDir = os.path.abspath(os.path.join(self.thugDir,relativeLogDir))
			xmlFile = "%s/analysis.xml" % logDir
			ret = self.parseXML(xmlFile, save_js_context)
			if ret is False:
				self.objects[0].addBool("thug_active",False)
				self.objects[0].addString("thug_error_message",str(output[1]))			
				
			else:
				self.objects[0].addBool("thug_active",True)
				self.objects[0].addBytes("thug_analysis_file",self.dsAdapter.putFile(xmlFile,self.currentTask.job))
				if save_zip:
					self.storeZip(logDir)

				bList = ow.toBehaviorList(ret[0])
				tmp = tempfile.mkstemp()
				os.write(tmp[0], bList.SerializeToString())
				os.close(tmp[0])
				self.objects[0].addBytes("thug_behaviors",self.dsAdapter.putFile(tmp[1],self.currentTask.job))

				os.remove(tmp[1])
#				logging.debug(ret[1])
				cList = ow.toJSContextList(ret[1])
				tmp = tempfile.mkstemp()
				os.write(tmp[0], cList.SerializeToString())
				os.close(tmp[0])
				self.objects[0].addBytes("js_context_list",self.dsAdapter.putFile(tmp[1],self.currentTask.job))
				os.remove(tmp[1])
		return []

	def runExternal(self,args):
		logging.debug(args)
		# Such a cwd will cause the logs to be written at '/opt/hsn2/thug/logs'
		proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.thugDir)
		output = proc.communicate()
		if proc.returncode != 0:
			raise ProcessingException("Thug returncode was %d" % proc.returncode)
		return output

	def parseXML(self, xmlFile, saveJsContext):
		if os.path.isfile(xmlFile):
			ret = self.parser.parseFile(xmlFile, saveJsContext)
			return ret
		else:
			return False

	def storeZip(self, dirPath):
		zip = shutil.make_archive(dirPath, "zip", dirPath, dirPath, verbose=False)
		self.objects[0].addBytes("thug_analysis_zip",self.dsAdapter.putFile(zip,self.currentTask.job))
		logging.debug("'%s' zip stored" % zip)
		os.remove(zip)
