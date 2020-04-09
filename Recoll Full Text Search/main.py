#!/usr/bin/env python
# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:ai
from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

__license__   = 'GPL v3'
__copyright__ = '2013, Stanislav Kazmin'
__docformat__ = 'restructuredtext en'

if False:
    # This is here to keep my python error checker from complaining about
    # the builtin functions that will be defined by the plugin loading system
    # You do not need this code in your plugins
    get_icons = get_resources = None


from PyQt5.Qt import (QDialog, QVBoxLayout, QPushButton, QMessageBox, QLabel, 
                      QLineEdit, QComboBox,  QCompleter,  QMainWindow,  QWidget,  QTextEdit)
from calibre_plugins.recoll_fulltext_search.config import prefs

from subprocess import Popen, PIPE, STDOUT
import re

class AboutWindow(QMainWindow):
    def __init__(self, parent=None):
        QMainWindow.__init__(self, parent)
        self.create_main_frame()       

    def create_main_frame(self):        
        page = QWidget()        

        self.button = QPushButton('OK', page)
        self.textWindow = QTextEdit()

        vbox1 = QVBoxLayout()
        vbox1.addWidget(self.textWindow)
        vbox1.addWidget(self.button)
        page.setLayout(vbox1)
        self.setCentralWidget(page)

        self.button.clicked.connect(self.clicked)

    def clicked(self):
        self.close()

class RecollFulltextSearchDialog(QDialog):

    def __init__(self, gui, icon, do_user_config):
        QDialog.__init__(self, gui)
        self.gui = gui
        self.do_user_config = do_user_config

        # The current database shown in the GUI
        # db is an instance of the class LibraryDatabase2 from database.py
        # This class has many, many methods that allow you to do a lot of
        # things.
        self.db = gui.current_db

        self.l = QVBoxLayout()
        self.setLayout(self.l)
        


        # Label
        self.labelText = QLabel('Use "and" and "or" for the search.')
        self.l.addWidget(self.labelText)

        # Title
        self.setWindowTitle('Recoll Full Text Search')
        self.setWindowIcon(icon)

        # Search window
        self.searchTextWindow = QComboBox()
        self.searchTextWindow.setEditable(True)
        self.l.addWidget(self.searchTextWindow)
        self.searchTextWindow.setFocus()
        self.searchTextWindow.setInsertPolicy(QComboBox.NoInsert)
        self.searchTextWindow.setDuplicatesEnabled(False)
        
        #Completer for the seach window
        self.completer = QCompleter()
        self.completer.setCompletionMode( QCompleter.UnfilteredPopupCompletion )
        self.searchTextWindow.setCompleter(self.completer)
        
        # output window
        self.outputWindow = QLabel()
        self.l.addWidget(self.outputWindow)
        
        # search button 1
        self.doSearchButton = QPushButton('Search and replace the filter', self)
        self.doSearchButton.clicked.connect(self.recollSearchNew)
        self.l.addWidget(self.doSearchButton)
        self.doSearchButton.setDefault(True)
                
        # search button 2
        self.doSearchButton = QPushButton('Search and add to filter', self)
        self.doSearchButton.clicked.connect(self.recollSearchAdd)
        self.l.addWidget(self.doSearchButton)
    
        # update database button 1
        self.updateDatabaseButton = QPushButton('Update recoll database', self)
        self.updateDatabaseButton.clicked.connect(self.updateDatabase)
        self.l.addWidget(self.updateDatabaseButton)
        
        # update database button 2
        self.newDatabaseButton = QPushButton('Make new recoll database', self)
        self.newDatabaseButton.clicked.connect(self.newDatabase)
        self.l.addWidget(self.newDatabaseButton)
        
        # config button
        self.configButton = QPushButton('Configure this plugin', self)
        self.configButton.clicked.connect(self.config)
        self.l.addWidget(self.configButton)
        
        # about button
        self.aboutButton = QPushButton('About', self)
        self.aboutButton.clicked.connect(self.about)
        self.l.addWidget(self.aboutButton)

        self.resize(self.sizeHint())
        #self.resize(500, self.height())
        

    def about(self):
        # Get the about text from a file inside the plugin zip file
        # The get_resources function is a builtin function defined for all your
        # plugin code. It loads files from the plugin zip file. It returns
        # the bytes from the specified file.
        
        text = get_resources('about.txt')
        #box = QMessageBox()
        #box.about(self, 'About the Recoll Full Text Search \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t',text.decode('utf-8'))
        #self.resize(600, self.height())
        
        self.box = AboutWindow()
        self.box.setWindowTitle("About the Recoll Full Text Search Plugin")
        self.box.textWindow.setText(text)
        self.box.textWindow.setReadOnly(True)
        self.box.resize(600, 500)
        self.box.show()
        

    def updateDatabase(self):
        self.replaceDatabase =False
        self.makeDatabase()

    def newDatabase(self):
        self.replaceDatabase = True
        self.makeDatabase()

    def recollSearchNew(self):
        self.searchAdd = False
        self.recollSearch()
    
    def recollSearchAdd(self):
        self.searchAdd = True
        self.recollSearch()

    def makeDatabase(self):
        '''Runs recollindex outside calibre like in a terminal. 
        Look for recollindex for more information about the flags and options'''
        self.cmd = [prefs['pathToRecoll'] + '/recollindex', '-c', prefs['pathToCofig'] + '/plugins/recollFullTextSearchPlugin']
        #TODO: Fix for Linux
        #self.cmd = 'LD_LIBRARY_PATH="" ' + prefs['pathToRecoll'] + '/recollindex -c ' + prefs['pathToCofig'] + '/plugins/recollFullTextSearchPlugin'
        if self.replaceDatabase == True :
            self.cmd += [' -z']
        self.p = Popen(self.cmd,  shell=False)
        # TODO: Was close_fds nessesary? check it on linux
        #self.p = Popen(self.cmd,  shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

        box = QMessageBox()
        box.about(self, 'Please read! \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t','Depending on you library size this operation can take a lot of time.\nThe process runs outside calibre so you can use or close it, but do not use this plugin.\nFor now there is no information about when recoll finishs,\nso look up, whether a recoll of recollindex process is running on you system.')

    def recollSearch(self):
        '''Runs recoll outside calibre like in a terminal. 
        Look for recollindex for more information about the flags and options'''
        self.searchText = str(self.searchTextWindow.currentText())# search text from the plugin gui
        self.searchTextWindow.insertItem(0, self.searchText)
        print ("Search text is "+self.searchText)
        print (type(self.searchText))

        #convert to Windows Russian Console CP
        #Python3 version should be?
        #b=bytes(self.searchText,"utf-8")
        #s=str(b,"cp866")
        #self.searchTextConsole=s
        #Python2 version
        self.searchTextConsole=self.searchText.decode("utf-8")
 
        #TODO: Fix Linux
        #self.cmd = 'LD_LIBRARY_PATH="" ' + prefs['pathToRecoll'] + '/recoll -c ' + prefs['pathToCofig'] + '/plugins/recollFullTextSearchPlugin -b -t '
        self.cmd = [prefs['pathToRecoll'] + '/recoll', '-c', prefs['pathToCofig'] + '/plugins/recollFullTextSearchPlugin', '-b', '-t']
        self.cmdString = self.cmd + [self.searchTextConsole]
        # TODO: Was close_fds nessesary? check it on linux
        #self.p = Popen(self.cmdString,  shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        self.p = Popen(self.cmdString,  shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        self.output = self.p.stdout.read()# output from the recoll search
        #print ("Search result is "+self.output.decode('cp866'))

        self.found = list(set(re.findall(r" \((\d+)\)\/[^/]*", self.output)))# regex to find the calibre ids in the folder names
        
        self.wholeString = ''
        if len(self.found) == 0 :
            self.outputWindow.setText('no books found' + ' for ' + self.searchText)
        else :
            for elem in self.found[:400]:
                self.wholeString += 'id:=' + elem + ' or '
            self.wholeString = self.wholeString[:-4]
            if len(self.found) > 400 :
                self.outputWindow.setText(str(len(self.found)) + ' books found' + ' for ' + self.searchText+ '. Only the first 400 books are shown')
            else :
                self.outputWindow.setText(str(len(self.found)) + ' books found' + ' for ' + self.searchText)

        if self.searchAdd == True :
            self.oldFilter = self.gui.search.text()
            self.wholeString = self.oldFilter + ' and (' + self.wholeString + ')'
        
        self.searchTextWindow.clearEditText()
        self.gui.search.setEditText(self.wholeString) # set calibre search to the string found by recoll
        self.gui.search.do_search()

    def config(self):
        self.do_user_config(parent=self)

# import of win_subprocess doesn't work? ok
# Windows only!!!
## issue: https://bugs.python.org/issue19264

import ctypes
import subprocess
import _subprocess
from ctypes import byref, windll, c_char_p, c_wchar_p, c_void_p, \
     Structure, sizeof, c_wchar, WinError
from ctypes.wintypes import BYTE, WORD, LPWSTR, BOOL, DWORD, LPVOID, \
     HANDLE

import os

##
## Types
##

CREATE_UNICODE_ENVIRONMENT = 0x00000400
LPCTSTR = c_char_p
LPTSTR = c_wchar_p
LPSECURITY_ATTRIBUTES = c_void_p
LPBYTE  = ctypes.POINTER(BYTE)

class STARTUPINFOW(Structure):
    _fields_ = [
        ("cb",              DWORD),  ("lpReserved",    LPWSTR),
        ("lpDesktop",       LPWSTR), ("lpTitle",       LPWSTR),
        ("dwX",             DWORD),  ("dwY",           DWORD),
        ("dwXSize",         DWORD),  ("dwYSize",       DWORD),
        ("dwXCountChars",   DWORD),  ("dwYCountChars", DWORD),
        ("dwFillAtrribute", DWORD),  ("dwFlags",       DWORD),
        ("wShowWindow",     WORD),   ("cbReserved2",   WORD),
        ("lpReserved2",     LPBYTE), ("hStdInput",     HANDLE),
        ("hStdOutput",      HANDLE), ("hStdError",     HANDLE),
    ]

LPSTARTUPINFOW = ctypes.POINTER(STARTUPINFOW)


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",         HANDLE), ("hThread",          HANDLE),
        ("dwProcessId",      DWORD),  ("dwThreadId",       DWORD),
    ]

LPPROCESS_INFORMATION = ctypes.POINTER(PROCESS_INFORMATION)


class DUMMY_HANDLE(ctypes.c_void_p):

    def __init__(self, *a, **kw):
        super(DUMMY_HANDLE, self).__init__(*a, **kw)
        self.closed = False

    def Close(self):
        if not self.closed:
            windll.kernel32.CloseHandle(self)
            self.closed = True

    def __int__(self):
        return self.value


CreateProcessW = windll.kernel32.CreateProcessW
CreateProcessW.argtypes = [
    LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION,
]
CreateProcessW.restype = BOOL


##
## Patched functions/classes
##

def CreateProcess(executable, args, _p_attr, _t_attr,
                  inherit_handles, creation_flags, env, cwd,
                  startup_info):
    """Create a process supporting unicode executable and args for win32

    Python implementation of CreateProcess using CreateProcessW for Win32

    """

    si = STARTUPINFOW(
        dwFlags=startup_info.dwFlags,
        wShowWindow=startup_info.wShowWindow,
        cb=sizeof(STARTUPINFOW),
        ## XXXvlab: not sure of the casting here to ints.
        hStdInput=int(startup_info.hStdInput),
        hStdOutput=int(startup_info.hStdOutput),
        hStdError=int(startup_info.hStdError),
    )

    wenv = None
    if env is not None:
        ## LPCWSTR seems to be c_wchar_p, so let's say CWSTR is c_wchar
        env = (unicode("").join([
            unicode("%s=%s\0") % (k, v)
            for k, v in env.items()])) + unicode("\0")
        wenv = (c_wchar * len(env))()
        wenv.value = env

    pi = PROCESS_INFORMATION()
    creation_flags |= CREATE_UNICODE_ENVIRONMENT

    if CreateProcessW(executable, args, None, None,
                      inherit_handles, creation_flags,
                      wenv, cwd, byref(si), byref(pi)):
        return (DUMMY_HANDLE(pi.hProcess), DUMMY_HANDLE(pi.hThread),
                pi.dwProcessId, pi.dwThreadId)
    raise WinError()


def smart_str(x):
    if isinstance(x, unicode):
        return unicode(x).encode("utf-8")
    elif isinstance(x, int) or isinstance(x, float):
        return str(x)
    return x

def my_list2cmdline(seq):
    """
    Translate a sequence of arguments into a command line
    string, using the same rules as the MS C runtime:

    1) Arguments are delimited by white space, which is either a
       space or a tab.

    2) A string surrounded by double quotation marks is
       interpreted as a single argument, regardless of white space
       contained within.  A quoted string can be embedded in an
       argument.

    3) A double quotation mark preceded by a backslash is
       interpreted as a literal double quotation mark.

    4) Backslashes are interpreted literally, unless they
       immediately precede a double quotation mark.

    5) If backslashes immediately precede a double quotation mark,
       every pair of backslashes is interpreted as a literal
       backslash.  If the number of backslashes is odd, the last
       backslash escapes the next double quotation mark as
       described in rule 3.
    """

    # See
    # http://msdn.microsoft.com/en-us/library/17w5ykft.aspx
    # or search http://msdn.microsoft.com for
    # "Parsing C++ Command-Line Arguments"
    result = []
    needquote = False
    for arg in seq:
        bs_buf = []

        # Add a space to separate this argument from the others
        if result:
            result.append(' ')

        needquote = (" " in arg) or ("\t" in arg) or not arg
        if needquote:
            result.append('"')

        print (u"Processing:"+arg)
        print (type(arg))
        for c in arg:
            if c == '\\':
                # Don't know if we need to double yet.
                bs_buf.append(c)
            elif c == '"':
                # Double backslashes.
                result.append('\\' * len(bs_buf)*2)
                bs_buf = []
                result.append('\\"')
            else:
                # Normal char
                if bs_buf:
                    result.extend(bs_buf)
                    bs_buf = []
                result.append(smart_str(c))

        # Add remaining backslashes, if any.
        if bs_buf:
            result.extend(bs_buf)

        if needquote:
            result.extend(bs_buf)
            result.append('"')

    return ''.join(result)



class Popen(subprocess.Popen):
    """This superseeds Popen and corrects a bug in cPython 2.7 implem"""

    def _execute_child(self, args, executable, preexec_fn, close_fds,
                       cwd, env, universal_newlines,
                       startupinfo, creationflags, shell, to_close,
                       p2cread, p2cwrite,
                       c2pread, c2pwrite,
                       errread, errwrite):
        """Code from part of _execute_child from Python 2.7 (9fbb65e)

        There are only 2 little changes concerning the construction of
        the the final string in shell mode: we preempt the creation of
        the command string when shell is True, because original function
        will try to encode unicode args which we want to avoid to be able to
        sending it as-is to ``CreateProcess``.

        """
        if not isinstance(args, subprocess.types.StringTypes):
            args = my_list2cmdline(args)

        if startupinfo is None:
            startupinfo = subprocess.STARTUPINFO()
        if shell:
            startupinfo.dwFlags |= _subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = _subprocess.SW_HIDE
            comspec = os.environ.get("COMSPEC", unicode("cmd.exe"))
            args = unicode('{} /c "{}"').format(comspec, args)
            if (_subprocess.GetVersion() >= 0x80000000 or
                    os.path.basename(comspec).lower() == "command.com"):
                w9xpopen = self._find_w9xpopen()
                args = unicode('"%s" %s') % (w9xpopen, args)
                creationflags |= _subprocess.CREATE_NEW_CONSOLE

        super(Popen, self)._execute_child(args, executable,
            preexec_fn, close_fds, cwd, env, universal_newlines,
            startupinfo, creationflags, False, to_close, p2cread,
            p2cwrite, c2pread, c2pwrite, errread, errwrite)

_subprocess.CreateProcess = CreateProcess