"""
Minimal SSH server
Just enough to simulate a connection.
"""

import sys

from zope.interface import implementer

from twisted.conch import avatar
from twisted.conch.checkers import InMemorySSHKeyDB, SSHPublicKeyChecker
from twisted.conch.ssh import connection, factory, keys, session, userauth
from twisted.conch.ssh.transport import SSHServerTransport
from twisted.cred import portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.internet import protocol, reactor
from twisted.protocols import basic
from twisted.python import components, log
import subprocess
import pathlib

log.startLogging(sys.stderr)


here = pathlib.Path(".")

if not (here / "build" / "host_rsa_key").exists():
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-N",  "", "-f", "build/host_rsa_key"],
        check=True,
    )
if not (here / "build" / "client_rsa_key").exists():
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-N",  "", "-f", "build/client_rsa_key"],
        check=True,
    )

"""
$ ssh -p 5022 -i ssh-keys/client_rsa user@localhost ls
"""

# Path to RSA SSH keys used by the server.
SERVER_RSA_PRIVATE = "build/host_rsa_key"
SERVER_RSA_PUBLIC = "build/host_rsa_key.pub"

# Path to RSA SSH keys accepted by the server.
CLIENT_RSA_PUBLIC = "build/client_rsa_key.pub"

PRIMES = {
    2048: [
        (
            2,
            int(
                "2426544657763384657581346888965894474823693600310397077868393"
                "3705240497295505367703330163384138799145013634794444597785054"
                "5748125479903006919561762337599059762229781976243372717454710"
                "2176446353691318838172478973705741394375893696394548769093992"
                "1001501857793275011598975080236860899147312097967655185795176"
                "0369411418341859232907692585123432987448282165305950904719704"
                "0150626897691190726414391069716616579597245962241027489028899"
                "9065530463691697692913935201628660686422182978481412651196163"
                "9303832327425472811802778094751292202887555413353357988371733"
                "1585493104019994344528544370824063974340739661083982041893657"
                "4217939"
            ),
        )
    ],
    4096: [
        (
            2,
            int(
                "8896338360072960666956554817320692705506152988585223623564629"
                "6621399423965037053201590845758609032962858914980344684974286"
                "2797136176274424808060302038380613106889959709419621954145635"
                "9745645498927756607640582597997083132103281857166287942205359"
                "2801914659358387079970048537106776322156933128608032240964629"
                "7706526831155237865417316423347898948704639476720848300063714"
                "8566690545913773564541481658565082079196378755098613844498856"
                "5501586550793900950277896827387976696265031832817503062386128"
                "5062331536562421699321671967257712201155508206384317725827233"
                "6142027687719225475523981798875719894413538627861634212487092"
                "7314303979577604977153889447845420392409945079600993777225912"
                "5621285287516787494652132525370682385152735699722849980820612"
                "3709076387834615230428138807577711774231925592999456202847308"
                "3393989687120016431260548916578950183006118751773893012324287"
                "3304901483476323853308396428713114053429620808491032573674192"
                "3854889258666071928702496194370274594569914312983133822049809"
                "8897129264121785413015683094180147494066773606688103698028652"
                "0892090232096545650051755799297658390763820738295370567143697"
                "6176702912637347103928738239565891710671678397388962498919556"
                "8943711148674858788771888256438487058313550933969509621845117"
                "4112035938859"
            ),
        )
    ],
}


class Avatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({b"session": session.SSHSession})


@implementer(portal.IRealm)
class Realm:

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], Avatar(avatarId), lambda: None


@implementer(session.ISession, session.ISessionSetEnv)
class Session:
    
    def __init__(self, _ignored):
        pass

    def execCommand(self, proto, cmd):
        if cmd.decode("ascii") == "ls":
            proto.write(b"some_file\n")
            proto.write(b"another_file\n")
        else:
            proto.write((repr(line)+ ": command not found").encode("ascii"))
        # Note: to properly close, there needs to be an ad-hoc fix to Twisted:
        #
        # def loseConnection(self):
        #     if self.client and self.client.transport:
        #         ...
        # in twisted/conch/ssh/session.py
        reactor.callLater(0, proto.processEnded)

    def closed(self):
        pass
    
    def eofReceived(self):
        pass

    def setEnv(self, key, value):
        pass


components.registerAdapter(
    Session, Avatar, session.ISession, session.ISessionSetEnv
)


def make_portal():
    sshDB = SSHPublicKeyChecker(
        InMemorySSHKeyDB({b"user": [keys.Key.fromFile(CLIENT_RSA_PUBLIC)]})
    )
    return portal.Portal(Realm(), [sshDB])


class Factory(factory.SSHFactory):

    protocol = SSHServerTransport
    # Service handlers.
    services = {
        b"ssh-userauth": userauth.SSHUserAuthServer,
        b"ssh-connection": connection.SSHConnection,
    }

    def __init__(self, portal):
        self.portal = portal


    def getPublicKeys(self):
        return {b"ssh-rsa": keys.Key.fromFile(SERVER_RSA_PUBLIC)}

    def getPrivateKeys(self):
        return {b"ssh-rsa": keys.Key.fromFile(SERVER_RSA_PRIVATE)}

    def getPrimes(self):
        return PRIMES


factory = Factory(make_portal())
reactor.listenTCP(5022, factory)
reactor.run()
