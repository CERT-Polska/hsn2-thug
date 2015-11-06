

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

import fcntl
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time

from hsn2_commons import hsn2objectwrapper as ow
from hsn2_commons.hsn2bus import ShutdownException
from hsn2_commons.hsn2osadapter import ObjectStoreException
from hsn2_commons.hsn2taskprocessor import HSN2TaskProcessor
from hsn2_commons.hsn2taskprocessor import ParamException
from hsn2_thug.hsn2thuganalysisparser import ThugAnalysisParser


ANALYSIS_DIR_REGEXP = re.compile(r"Thug analysis logs saved at\s([\.a-z0-9/]+)")


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

    def __init__(self, connector, datastore, serviceName, serviceQueue, objectStoreQueue, **extra):
        '''
        Runs Process init first and then creates required connections.
        '''
        HSN2TaskProcessor.__init__(self, connector, datastore, serviceName, serviceQueue, objectStoreQueue, **extra)
        self.thug = extra.get("thug")
        self.thugDir = os.path.dirname(self.thug)
        self.parser = ThugAnalysisParser()

    def taskProcess(self):
        '''	This method should be overridden with what is to be performed.
                Returns a list of warnings (warnings). The current task is available at self.currentTask'''
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
        delay = 3000
        timeout = 60 * 3
        threshold = 1024

        try:
            for param in self.currentTask.parameters:
                if param.name == "useragent":
                    value = str(param.value)
                    if value:
                        useragent = "--useragent=%s" % value
                elif param.name == "proxy":
                    value = str(param.value)
                    if value:
                        proxy = "--proxy=%s" % value
                elif param.name == "verbose":
                    verbose = self.paramToBool(param)
                    if verbose:
                        verbose = "--verbose"
                    else:
                        verbose = ""
                elif param.name == "debug":
                    debug = self.paramToBool(param)
                    if debug:
                        debug = "--debug"
                    else:
                        debug = ""
                elif param.name == "save_zip":
                    save_zip = self.paramToBool(param)
                elif param.name == "save_js_context":
                    save_js_context = self.paramToBool(param)
                elif param.name == "delay":
                    delay = int(param.value)
                    if delay < 0:
                        raise ParamException("%s" % "delay cannot be smaller than 0")
                elif param.name == "timeout":
                    timeout = int(param.value)
                    if timeout < 0:
                        raise ParamException("%s" % "timeout cannot be smaller than 0")
                elif param.name == "threshold":
                    threshold = int(param.value)
                    if threshold < 0:
                        raise ParamException("%s" % "threshold cannot be smaller than 0")
        except ParamException:
            raise
        except Exception as e:
            raise ParamException("%s" % str(e))

        delay = "--delay={}".format(delay)
        timeout_str = "--timeout={}".format(timeout)
        threshold = "--threshold={}".format(threshold) if threshold > 0 else ""
        args = ["/usr/bin/hsn2-limit-memory", "python", self.thug, "-F", "-M", timeout_str, delay, threshold, useragent, proxy, verbose, debug, referer, url]
        args = [unicode(x).encode("utf-8") for x in args if len(x) > 0]

        self.objects[0].addTime("thug_time_start", int(time.time() * 1000))
        output, timedout, return_code = self.runExternal(args, timeout * 1.5)

        if return_code != 0:
            if timedout:
                message = "Thug analysis timeout"
            else:
                message = "Thug returncode was {}".format(return_code)
            # logging.warning(output[0])
            logging.warning(message)
            self.objects[0].addString("thug_error", message)

            tmp = tempfile.mkstemp()
            os.write(tmp[0], output[0])
            os.close(tmp[0])
            self.objects[0].addBytes("thug_error_details", self.dsAdapter.putFile(tmp[1], self.currentTask.job))
            self.remove_tmp(tmp[1])
        else:
            self.objects[0].addTime("thug_time_stop", int(time.time() * 1000))
            if output[0] is not None:
                match = ANALYSIS_DIR_REGEXP.search(output[0])
                if match:
                    relativeLogDir = match.group(1)
                    logDir = os.path.abspath(os.path.join(self.thugDir, relativeLogDir))
                    xmlFile = "%s/analysis/maec11/analysis.xml" % logDir
                    ret = self.parseXML(xmlFile, save_js_context)
                    if ret is False:
                        self.objects[0].addString("thug_error", str(output[1]))
                    else:
                        logging.debug("Analysis parsed %s", xmlFile)

                    if save_zip and os.path.isdir(logDir):
                        self.storeZip(logDir)
                    self.remove_tmp(logDir)
                    parent_dir = os.path.dirname(logDir)
                    try:
                        os.rmdir(parent_dir)
                        logging.info("Removed log directory parent %s", parent_dir)
                    except:
                        logging.info("Couldn't remove log directory parent - non empty %s", parent_dir)
                else:
                    self.objects[0].addBool("thug_active", False)
                    self.objects[0].addString("thug_error", "Couldn't find log dir in output: " + repr(output[0]))
        return []

    def runExternal(self, args, timeout=60):
        """
        Execute args, limit execution time to 'timeout' seconds.
        Uses the subprocess module and subprocess.PIPE.
        """
        logging.debug(args)

        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=self.thugDir  # this will cause the logs to be written to '/opt/thug/logs' assuming that self.thugDir is '/opt/thug/src'
        )

        start = time.time()

        stdout_chunks = []
        stderr = ""

        timedout = False
        while proc.poll() is None:
            timedout = time.time() - start >= timeout
            if timedout:
                self.terminateProc(proc)
                break
            if not self.keepRunning:
                self.terminateProc(proc)
                raise ShutdownException("Shutdown while waiting for thug to finish processing")
            stdout_chunk = proc.stdout.read(100)
            if stdout_chunk:
                stdout_chunks.append(stdout_chunk)
            else:
                time.sleep(0.1)

        stdout_chunk = proc.stdout.read()
        if stdout_chunk:
            stdout_chunks.append(stdout_chunk)
        stdout = "".join(stdout_chunks)

        return (stdout, stderr), timedout, proc.returncode

    def terminateProc(self, proc):
        try:
            proc.stdout.close()
            proc.stderr.close()
            proc.terminate()
        except Exception as exc:
            logging.exception(exc)

    def parseXML(self, xmlFile, saveJsContext):
        (parsed, found_exploits, found_behaviours, found_js_contexts) = self.parser.parseFile(xmlFile, saveJsContext) if os.path.isfile(xmlFile) else False
        self.objects[0].addBool("thug_active", parsed)
        self.objects[0].addBool("thug_detected", found_exploits)

        if not parsed:
            return False

        self.objects[0].addBytes("thug_analysis_file", self.dsAdapter.putFile(xmlFile, self.currentTask.job))

        bList = ow.toBehaviorList(found_behaviours)
        tmp = tempfile.mkstemp()
        os.write(tmp[0], bList.SerializeToString())
        os.close(tmp[0])
        self.objects[0].addBytes("thug_behaviors", self.dsAdapter.putFile(tmp[1], self.currentTask.job))
        self.remove_tmp(tmp[1])

        cList = ow.toJSContextList(found_js_contexts)
        tmp = tempfile.mkstemp()
        os.write(tmp[0], cList.SerializeToString())
        os.close(tmp[0])
        self.objects[0].addBytes("js_context_list", self.dsAdapter.putFile(tmp[1], self.currentTask.job))
        self.remove_tmp(tmp[1])
        return True

    def storeZip(self, dirPath):
        zip_ = shutil.make_archive(dirPath, "zip_", dirPath, dirPath, verbose=False)
        self.objects[0].addBytes("thug_analysis_zip", self.dsAdapter.putFile(zip_, self.currentTask.job))
        logging.debug("'%s' zip_ stored" % zip_)
        os.remove(zip_)

    def remove_tmp(self, path):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except Exception as exc:
            logging.warning(u"Exception when trying to remove temporary files: %s %s", path, exc)
