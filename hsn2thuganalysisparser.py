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
Created on 31-05-2012

@author: wojciechm
'''
#import xml.parsers.expat
import xml.sax
import logging

class ThugAnalysisParser(xml.sax.handler.ContentHandler):
	parser = None
	behaviour = None
	behaviours = None
	inBehaviour = None
	inBehaviourText = None
	jsContext = None
	jsContexts = None
	inCodeSnippet = None
	inCodeSegment = None
	inCodeSegment = None

	def __init__(self):
		self.parser = xml.sax.make_parser()
		self.parser.setContentHandler(self)
		#self.parser = xml.parsers.expat.ParserCreate()

	def parseFile(self, filePath, saveJSContexts = True):
		self.behaviours = []
		self.jsContexts = []
		self.saveJSContexts = saveJSContexts
		self.inCodeSnippet = False
		self.inCodeSegment = False
		self.inBehaviour = False
		self.inBehaviourText = False
		#fileH = open(filePath,"r")
		try:
			self.parser.parse(filePath)
		except xml.sax.SAXException:
			return False
		#fileH.close()
		return (self.behaviours, self.jsContexts)

	# 3 handler functions
	def startElement(self, name, attrs):
		if self.saveJSContexts and name == "Code_Snippet" and attrs.getValueByQName("language") == "Javascript":
			self.inCodeSnippet = True
		if name == "Code_Segment" and self.inCodeSnippet:
			self.jsContext = ""
			self.inCodeSegment = True
		if name == "Behavior":
			self.behaviour = {}
			self.inBehaviour = True
		if self.inBehaviour and name == "Text":
			self.inBehaviourText = True
		if self.inBehaviour and name == "Discovery_Method":
			self.behaviour["discovery_method"] = attrs.getValueByQName("method")

	def endElement(self, name):
		if name == "Code_Snippet":
			if self.inCodeSegment:
				self.jsContexts.append({"id" : len(self.jsContexts)+1, "source" : self.jsContext, "eval" : False})
				self.jsContext = None
			self.inCodeSnippet = False
			self.inCodeSegment = False
		if name == "Behavior":
			self.inBehaviour = False
			self.inBehaviourText = False
			self.behaviours.append(self.behaviour)
			self.behaviour = None

	def characters(self, data):
		if self.inCodeSegment:
			self.jsContext = self.jsContext + data
		if self.inBehaviourText:
			self.behaviour["description_text"] = self.behaviour.get("description_text","") + data
