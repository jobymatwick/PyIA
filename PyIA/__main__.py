import logging
import sys

import config
import pia_api
import wireguard

conf = config.get()
logging.basicConfig(level=conf['log_level'].upper(), stream=sys.stdout)

if not wireguard.checkConfig():
    token = pia_api.getToken({'user': conf['username'], 'pass': conf['password']})
    region = pia_api.getRegionInfo(conf['region'])
    keypair = wireguard.createKeypair()
    conn_info = pia_api.authenticate(region, token, keypair['pubkey'])
    wireguard.createConfig(conn_info, keypair['prikey'])

if not wireguard.checkInterface():
    wireguard.connect()

wireguard.checkConnection()
