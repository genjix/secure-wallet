#!/usr/bin/env python

import httplib2
import json
import sys
import random
import time
import urllib2

import detwallet
import fastmonitor

def poll_latest_id():
    f = open("block-count")
    return int(f.read())

class Wallet:

    def __init__(self, master_public_key):
        self.sequence = -1
        self.detwallet = detwallet.DeterministicWallet()
        self.detwallet.set_master_public_key(master_public_key)

    def update(self, latest_id):
        if latest_id <= self.sequence:
            return []
        begin_id = self.sequence + 1
        addrs = []
        for i in range(begin_id, latest_id + 1):
            pubkey = self.detwallet.generate_public_key(i)
            addrs.append(detwallet.pubkey_to_address(pubkey))
        self.sequence = latest_id
        return addrs

class PeriodicMethod:

    def __init__(self, interval_time, callback):
        self.interval_time = interval_time
        self.callback = callback
        self.last_time = 0

    def __call__(self):
        now_time = time.time()
        if now_time - self.last_time > self.interval_time:
            self.callback()
            self.last_time = now_time

class Application:

    def __init__(self, wallet):
        self.wallet = wallet
        self.monitor = fastmonitor.FastMonitor()
        self.nonce = 0

    def start(self):
        self.http = httplib2.Http()
        self.monitor.start()
        self.run()

    def stop(self):
        self.monitor.stop()

    def run(self):
        update_wallet = PeriodicMethod(10, self.update_wallet)
        update_latest_block = PeriodicMethod(60, self.update_latest_block)
        while True:
            # Only calls every N seconds.
            update_wallet()
            update_latest_block()
            # Protection against timing attacks.
            time.sleep(random.random())
            # Pull in changed addresses and get updates for them.
            addrs = self.monitor.pull()
            for addr, tx_hash, output_index in addrs:
                self.update_address(addr)

    def update_wallet(self):
        latest_id = poll_latest_id()
        addrs = self.wallet.update(latest_id)
        for addr in addrs:
            self.monitor.push(addr)
            self.update_address(addr)

    def make_request(self, url):
        status, response = self.http.request(url)
        if status["status"] != '200':
            return None
        return json.loads(response)

    def update_latest_block(self):
        response = self.make_request("https://blockchain.info/latestblock")
        if response is None:
            print "Problem updating latest block"
            return False
        block_hash = response["hash"].decode("hex")
        self.monitor.set_latest_block(block_hash)
        return True

    def update_address(self, address):
        print "Address: ", address
        response = self.make_request("https://blockchain.info/unspent?active=%s" % address)
        if response is None:
            print "No spends available."
            return False
        unspent = response["unspent_outputs"]
        balances = [0, 0]
        for output in unspent:
            if output["confirmations"] >= 1:
                balances[1] += output["value"]
            else:
                balances[0] += output["value"]
        # POST this new balance now.
        self.post_balances(address, balances)
        return True

    def post_balances(self, address, balances):
        self.nonce += 1

mpk = "28070630d7c5103fc93784facb84113ded4831e73681b821f5799ebfeabeb2611cffc48bb40cf2f7e06300abf780241fa161818e8457f87b798a95beda82a712".decode("hex")
wallet = Wallet(mpk)
app = Application(wallet)
try:
    app.start()
except KeyboardInterrupt:
    print "Stopping..."
    app.stop()

