# Configuration #
Out of the box, omapd runs on port 8096 and accepts connections on https://host:8096.  You may need to open tcp port 8081 on your firewall.  To change configuration options, edit the
omapd.conf file.

# SSL #
SSL is enabled by default, though it can be disabled.  There is no default server certificate provided.  **With SSL enabled, connections will fail if you do not provide omapd with a private key and certificate.**

Obtain a server certificate and name it "server.pem" along with a private key named "server.key" and place them in the same directory as the omapd binary.  For convenience, there is a certgen.sh script that generates a self-signed cert that uses the first command-line arguement as the certificate's common name (CN).  You can edit this script to change the other distinguished name elements.

# MAP Graph Plugin #
omapd requires a plugin for storing the MAP Graph data.  A plugin is provided with omapd that simply stores the MAP data in RAM-based hash tables.  However, this plugin is a separate project in the plugins/ directory and needs to be built separately.