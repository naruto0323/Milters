
import StringIO
import functools


import Milter
from Milter.utils import parseaddr


import gnupg
import config

class GnupgMilter(Milter.Base):

    gpgm_pk = None
    gpgm_me = "gnupg-milter"

    
    gpgm_gpg = None

    def __init__(self, conf=None):  
        self.id = Milter.uniqueID()
        if conf is not None:
            assert isinstance(conf, config.Config)
            self.conf = conf
        else:
            self.conf = config.Config()
        self.gpgm_gpg = gnupg.GPG(gnupghome=self.conf.gnupghome)

    @Milter.noreply
    def connect(self, IPname, family, hostaddr):
        '''
        incoming connection

        example parameters:
            IPname='mx.example.com', family=AF_INET, hostaddr=('23.5.4.3',4720)
            ..., family=AF_INET6, hostaddr=('3ffe:80e8:d8::1', 4720, 1, 0)
        '''
        self.gpgm_body = None
        config.log("connect from %s at %s" % (IPname, hostaddr))
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *s):
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, to, *s):
        toName, toAddr = parseaddr(to)
        self.gpgm_pk = self.gpgm_get_public_key_fingerprint(toAddr)
        if self.gpgm_pk is not None:
            self.conf.log("Have private key for {}:\n{}".format(toAddr, self.gpgm_pk))
        else:
            self.conf.log("No private key for {}.".format(toAddr))
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, hval):
        return Milter.CONTINUE

    @Milter.noreply
    def eoh(self):
        self.gpgm_body = StringIO.StringIO()
        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):
      
        self.gpgm_body.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        if self.gpgm_pk:
            self.addheader("X-encrypted-by", self.gpgm_me)
        else:
            self.addheader("X-parsed-by", self.gpgm_me)
        self.gpgm_body.seek(0)
        self.conf.log("The whole message:\n{}".format(self.fp.read()))
        if self.gpgm_pk:
            self.conf.log("Crypted body:\n{]".format(self.gpgm_encrypt()))
        else:
            self.conf.log("Not encrypting...")
     
        return Milter.ACCEPT

    def close(self):
        self.body.close()
        return Milter.CONTINUE

    def abort(self):
       
        return Milter.CONTINUE

  
    @staticmethod
    def gpgm_get_factory(conf=None):
        return functools.partial(GnupgMilter, conf=conf)

    @staticmethod
    def gpgm_canonical_email_address(addr):
        return addr.strip().lower()

    def gpgm_get_public_key_fingerprint(self, addr):
        for k in self.gpgm_gpg.list_keys():
            for uid in k['uids']:
                name, caddr = parseaddr(uid)
                canonical_curr = self.gpgm_canonical_email_address(caddr)
                canonical_search = self.gpgm_canonical_email_address(addr)
                if  canonical_curr == canonical_search:
                    self.conf.log("Found fingerprint")
                    return k['fingerprint']

        return ""

    def gpgm_encrypt(self, data, fingerprint):
        assert isinstance(data, str), "Only strings can be encrypted."
        if len(str) == 0:
            return ""
        
        enc = self.gpgm_gpg.encrypt(data, fingerprint)
        assert len(enc)>0, "Encryption failed."
        return enc

