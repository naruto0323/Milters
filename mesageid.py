
import codecs
import libmilter as lm
import os
import socket
import sys
import time


class MessageIDMilter(lm.ThreadMixin, lm.MilterProtocol):
   
    has_messageid = False

    def __init__(self, opts=0, protos=lm.SMFIP_ALLPROTOS ^ lm.SMFIP_NOHDRS):
       
        # inherit parents
        lm.MilterProtocol.__init__(self, opts, protos)
        lm.ThreadMixin.__init__(self)

    def log(self, message):
        print >> sys.stdout, message
        sys.stdout.flush()

    def header(self, key, val, cmdDict):
        if key.lower() == "message-id":
            self.has_messageid = True
        return lm.CONTINUE

    def eob(self, cmdDict):
        if self.has_messageid:
            self.has_messageid = False
            return lm.CONTINUE
        else:
            key = "Message-ID"
            val = self.create_messageid()
            self.log("Message without Message-ID received. "
                     "Adding header: {!s} with value {!s}".format(key, val))
            self.addHeader(key, val)
            return lm.CONTINUE

    def close(self)
       
        self.has_messageid = False

    def abort(self):
      
        self.has_messageid = False

    def create_messageid(self):
        
        microseconds = codecs.decode(str(int(time.time() * 1000000)), "utf8")
        random_part = codecs.encode(os.urandom(8), "hex").decode("utf8")
        fqdn = socket.getfqdn()
        if not fqdn:
            fqdn = codecs.encode(os.urandom(8), "hex").decode("utf8")
        return " <" + microseconds + "." + random_part + "@" + fqdn + ">"


def run_messageidmilter():
    import signal

    socketpath = "/root/milter"
    try:
        os.mkdir(socketpath, 0o755)
    except OSError:

        pass
    socketname = "messageidmilter"


    opts = lm.SMFIF_ADDHDRS


    factory = lm.ThreadFactory(socketpath + "/" + socketname,
                               MessageIDMilter, opts)

    def sighandler(signum, frame):
        factory.close()
        sys.exit(1)

    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGQUIT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)

    try:
        factory.run()
    except Exception:
        e = sys.exc_info()
        print >> sys.stderr, "EXCEPTION OCCURRED: {!s}".format(e)
        factory.close()
        raise


if __name__ == "__main__":
    run_messageidmilter()
