

VERSION = '0.4'
ANCHOR = '/var/lib/unbound/root.anchor'
OPENPGPKEY = 61

import Milter
import StringIO
import time
import email
import sys
import os
import shutil
import argparse
from hashlib import sha224

from socket import AF_INET6
from Milter.utils import parse_addr
if True:
    from multiprocessing import Process as Thread, Queue
else:
    from threading import Thread
    from Queue import Queue

logq = Queue(maxsize=4)

from syslog import syslog, openlog, LOG_MAIL
try:
    openlog('openpgpkey-milter', facility=LOG_MAIL)
except:
    # for python 2.6
    openlog('openpgpkey-milter', LOG_MAIL)

try:
    import setproctitle
    setproctitle.setproctitle("openpgpkey-milter")
except:
    syslog('openpgpkey-milter: failed to setproctitle - python-setproctitle missing?')

import unbound
ctx = unbound.ub_ctx()
ctx.resolvconf('/etc/resolv.conf')
try:
    if os.path.isfile(ANCHOR):
       ctx.add_ta_file(ANCHOR)
except:
    pass

spool_dir = '/var/spool/openpgpkey-milter'

import gnupg

class myMilter(Milter.Base):

    def __init__(self): 
        self.id = Milter.uniqueID()  



    @Milter.noreply
    def connect(
        self,
        IPname,
        family,
        hostaddr,
        ):
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
        syslog('connect from %s at %s' % (IPname, hostaddr))
        return Milter.CONTINUE



    def hello(self, heloname):

   
        self.H = heloname
        
        return Milter.CONTINUE

 
    def envfrom(self, mailfrom, *str):
        self.F = mailfrom
        self.R = []  
        self.fromparms = Milter.dictfromlist(str)  
        self.user = self.getsymval('{auth_authen}')  
       

        self.fp = StringIO.StringIO()
        self.canon_from = '@'.join(parse_addr(mailfrom))
        self.fp.write('From %s %s\n' % (self.canon_from, time.ctime()))
        return Milter.CONTINUE



    @Milter.noreply
    def envrcpt(self, to, *str):
        rcptinfo = (to, Milter.dictfromlist(str))
        self.R.append(rcptinfo)
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, hval):
        self.fp.write('%s: %s\n' % (name, hval))  
        return Milter.CONTINUE

    @Milter.noreply
    def eoh(self):
        self.fp.write('\n') 
        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):
        self.fp.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        self.fp.seek(0)
        subject = 'none'


        self.addheader('X-OPENPGPKEY', 'Message passed unmodified' , 1)
        msg = email.message_from_file(self.fp)
     


      
        if msg.is_multipart():
            syslog('Multipart message type passed unmodified')
            return Milter.CONTINUE

        gpgdir = '%s/%s' % (spool_dir, self.id)
        if os.path.isdir(gpgdir):
            shutil.rmtree(gpgdir)
        os.mkdir(gpgdir)
        tos = msg.get_all('to', [])
        ccs = msg.get_all('cc', [])
        all_recipients = email.utils.getaddresses(tos + ccs)
        recipients = []
        for entry in all_recipients:
            recipients.append(entry[1])
     
        gpg = gnupg.GPG(gnupghome=gpgdir)
        gpg.decode_errors="ignore"
        for recipient in recipients:
            (username, domainname) = recipient.split('@')
            rfcname = sha224(username).hexdigest()
            qname = '%s._openpgpkey.%s' % (rfcname, domainname)
            (status, result) = ctx.resolve(qname, OPENPGPKEY,
                    unbound.RR_CLASS_IN)
            if status != 0:
                syslog("unbound openpgpkey lookup for '%s' returned non-zero status, deferring" % recipient)
                return Milter.TEMPFAIL
            if result.rcode_str == 'serv fail':
                syslog("unbound openpgpkey lookup for '%s' returned SERVFAIL, deferring" % recipient)
                return Milter.TEMPFAIL
            if result.bogus:
                syslog("unbound openpgpkey lookup for '%s' returned with INVALID DNSSEC data, deferring" % recipient)
                return Milter.TEMPFAIL
            if not result.secure:
                syslog("unbound openpgpkey lookup for '%s' ignored as the domain is not signed with DNSSEC - letting go plaintext" % recipient)
                return Milter.CONTINUE
            if not result.havedata:
                syslog("unbound openpgpkey lookup for '%s' succeeded but no OpenPGP key publishd - letting go plaintext" % recipient)
                return Milter.CONTINUE

            for openpgpkey in result.data.raw:
                import_result = gpg.import_keys(openpgpkey)

      
        fingerprints = []
        imported_keys = gpg.list_keys()
        for ikey in imported_keys:
            syslog('Received DNSSEC secured OPENPGPKEY for %s: Key-ID:%s Fingerprint:%s'
                    % (recipient, ikey['keyid'], ikey['fingerprint']))
            fingerprints.append(ikey['fingerprint'])
        fpliststr = ','.join(fingerprints)

        if 'subject' in msg:
            subject = msg['subject']
        msgstr = '''Subject:%s %s''' % (subject, msg)
        if '-----BEGIN PGP MESSAGE-----' in msgstr:
         
            syslog('Message already encrypted - letting it go unmodified')
            return Milter.CONTINUE

        gpg = gnupg.GPG(gnupghome=gpgdir)
        gpg.decode_errors="ignore"
        syslog('Will encrypt message to fingerprints:%s' % fpliststr)
        enc_msg = gpg.encrypt(msgstr, fingerprints, always_trust=True)
        if enc_msg.data == '':
         
            syslog('Encryption to %s failed - failing message for retry later' % fpliststr)
            return Milter.TEMPFAIL

        self.chgheader('User-Agent', 1, 'dkim-openpgpkey')
        self.chgheader('Subject', 1, '[openpgpkey-milter encrypted message]')
        self.chgheader('X-OPENPGPKEY', 1, 'Encrypted to key(s): %s ' % fpliststr)

      
        self.replacebody(enc_msg.data)

        return Milter.ACCEPT

    def close(self):
      
        gpgdir = '%s/%s' % (spool_dir, self.id)
        if os.path.isdir(gpgdir):
            shutil.rmtree(gpgdir)
        return Milter.CONTINUE

    def abort(self):

        return Milter.CONTINUE




def background():
    while True:
        t = logq.get()
        if not t:
            break
        (msg, mid, ts) = t
        mymsgs = ''
        for i in msg:
            mymsgs += '%s ' % i
        syslog('backgrounding [%d] ' % mid, mymsgs)

## ===

def main():
    global spool_dir
    global ctx
    parser = \
        argparse.ArgumentParser(description='OPENPGPKEY milter application'
                                , epilog='For bugs. see paul@nohats.ca')
    parser.add_argument('--anchor', '-a', action='store', default='',
                        help='location of the unbound DNSSEC trust anchor file (default /var/lib/unbound/root.anchor')
    parser.add_argument('--port', '-p', action='store', default='8890',
                        help='port on localhost to use (default 8890)')
    parser.add_argument('--pid', '-P', action='store', default='',
                        help='pidfile to create (default no pid file is created')
    parser.add_argument('--rrtype', '-r', action='store',
                        default='65280',
                        help='RRtype allocation (default private use 65280)')
    parser.add_argument('--spool', '-s', action='store',
                        default='/var/spool/openpgpkey-milter',
                        help='spool dir for tmp files (default /var/spool/openpgpkey-milter)')
    parser.add_argument('--timeout', '-t', action='store', default=600,
                        help='timeout (default 600)')
    parser.add_argument('--version', action='store_true',
                        help='show version and exit')
    args = parser.parse_args()
    if args.version:
        print 'openpgpkey-milter version %s by Paul Wouters <paul@cypherpunks.ca>' % VERSION
        print '     options: --rrtype %s --spool %s  --port %s  --timeout %s --pid <pidfile>' % (args.rrtype, args.spool, args.port, args.timeout)
        sys.exit()

    if args.anchor:
        if not os.path.isfile(args.anchor):
           sys.exit("anchor file '%s' does not exist"%args.anchor)
        ctx.add_ta_file(args.anchor)

    socketname = 'inet:%s@127.0.0.1' % args.port
    spool_dir = args.spool

    bt = Thread(target=background)
    bt.start()

    # Register to have the Milter factory create instances of your class:
    Milter.factory = myMilter
    flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
    flags += Milter.ADDRCPT
    flags += Milter.DELRCPT
    Milter.set_flags(flags)

    mypid = str(os.getpid())
    if args.pid:
       try:
            fp = open(args.pid,"w")
            fp.write(mypid)
            fp.close()
       except:
              sys.exit("Failed to write pid, aborted")

    syslog('starting daemon [%s] version %s on port %s at %s with timeout %s'
            % (mypid, VERSION, args.port, args.spool, args.timeout))
    sys.stdout.flush()
    Milter.runmilter('pythonfilter', socketname, args.timeout)
    logq.put(None)
    bt.join()
    syslog('shutting down daemon')

    if os.path.isfile(args.pid) and not os.path.islink(args.pid):
       os.unlink(args.pid)

if __name__ == '__main__':
    main()
