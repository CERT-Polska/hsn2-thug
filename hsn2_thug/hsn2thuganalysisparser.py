#!/usr/bin/python -tt

# Copyright (c) NASK
#
# This file is part of HoneySpider Network 2.1.
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

import xml.sax


class ThugAnalysisParser(xml.sax.handler.ContentHandler):
    parser = None
    found_exploits = None
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

    def parseFile(self, filePath, saveJSContexts=True):
        self.behaviours = []
        self.jsContexts = []
        self.saveJSContexts = saveJSContexts
        self.inCodeSnippet = False
        self.inCodeSegment = False
        self.inBehaviour = False
        self.inBehaviourText = False
        self.found_exploits = False
        try:
            self.parser.parse(filePath)
        except xml.sax.SAXException:
            return (False, False, False, False)
        return (True, self.found_exploits, self.behaviours, self.jsContexts)

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
        if self.inBehaviour and name == "Attempted_Vulnerability_Exploit":
            self.found_exploits = True
        if self.inBehaviour and name == "Text":
            self.inBehaviourText = True
        if self.inBehaviour and name == "Discovery_Method":
            self.behaviour["discovery_method"] = attrs.getValueByQName("method")

    def endElement(self, name):
        if name == "Code_Snippet":
            if self.inCodeSegment:
                self.jsContexts.append({"id": len(self.jsContexts) + 1, "source": self.jsContext, "eval": False})
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
            self.behaviour["description_text"] = self.behaviour.get("description_text", "") + data
