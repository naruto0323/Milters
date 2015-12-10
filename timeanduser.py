

import Milter
import StringIO
import time
import email
import sys
from socket import AF_INET, AF_INET6
from Milter.utils import parse_addr
if True:
  from multiprocessing import Process as Thread, Queue
else:
  from threading import Thread
  from Queue import Queue

logq = Queue(maxsize=4)

class myMilter(Milter.Base):

  def __init__(self): 
    self.id = Milter.uniqueID() 

 
  @Milter.noreply
  def connect(self, IPname, family, hostaddr):
   
    self.IP = hostaddr[0]
    self.port = hostaddr[1]
    if family == AF_INET6:
      self.flow = hostaddr[2]
      self.scope = hostaddr[3]
    else:
      self.flow = None
      self.scope = None
    self.IPname = IPname  
    self.H = None
    self.fp = None
    self.receiver = self.getsymval('j')
    self.log("connect from %s at %s" % (IPname, hostaddr) )
    
    return Milter.CONTINUE



  def hello(self, heloname):
    
    self.H = heloname
    self.log("HELO %s" % heloname)
    if heloname.find('.') < 0:	# illegal helo name
      
      self.setreply('550','5.7.1','Sheesh people!  Use a proper helo name!')
      return Milter.REJECT
      
    return Milter.CONTINUE

  
  def envfrom(self, mailfrom, *str):
    self.F = mailfrom
    self.R = [] 
    self.fromparms = Milter.dictfromlist(str)	
    self.user = self.getsymval('{auth_authen}')	
    self.log("mail from:", mailfrom, *str)
   
    self.fp = StringIO.StringIO()
    self.canon_from = '@'.join(parse_addr(mailfrom))
    self.fp.write('From %s %s\n' % (self.canon_from,time.ctime()))
    return Milter.CONTINUE


  ##  def envrcpt(self, to, *str):
  @Milter.noreply
  def envrcpt(self, to, *str):
    rcptinfo = to,Milter.dictfromlist(str)
    self.R.append(rcptinfo)
    
    return Milter.CONTINUE


  @Milter.noreply
  def header(self, name, hval):
    self.fp.write("%s: %s\n" % (name,hval))	
    return Milter.CONTINUE

  @Milter.noreply
  def eoh(self):
    self.fp.write("\n")				
    return Milter.CONTINUE

  @Milter.noreply
  def body(self, chunk):
    self.fp.write(chunk)
    return Milter.CONTINUE

  def eom(self):
    self.fp.seek(0)
    msg = email.message_from_file(self.fp)
   
    self.addrcpt('<%s>' % 'spy@example.com')
    return Milter.ACCEPT

  def close(self):
   
    return Milter.CONTINUE

  def abort(self):
  
    return Milter.CONTINUE



  def log(self,*msg):
    logq.put((msg,self.id,time.time()))

def background():
  while True:
    t = logq.get()
    if not t: break
    msg,id,ts = t
    print "%s [%d]" % (time.strftime('%Y%b%d %H:%M:%S',time.localtime(ts)),id),
    
    for i in msg: print i,
    print

def main():
  bt = Thread(target=background)
  bt.start()
  socketname = "/home/stuart/pythonsock"
  timeout = 600
 
  Milter.factory = myMilter
  flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
  flags += Milter.ADDRCPT
  flags += Milter.DELRCPT
  Milter.set_flags(flags)      
  print "%s milter startup" % time.strftime('%Y%b%d %H:%M:%S')
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,timeout)
  logq.put(None)
  bt.join()
  print "%s bms milter shutdown" % time.strftime('%Y%b%d %H:%M:%S')

if __name__ == "__main__":
  main()
