#!/usr/bin/env python

from collections import defaultdict
import hashlib
import sys
import time
import deserialize
import detwallet
import electrum

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

class Interface:

    def start(self):
        self.interface = electrum.Interface({"server": "ecdsa.org:50001:t"})
        self.interface.start()
        for i in range(8):
            if self.interface.is_connected:
                break
            time.sleep(1)
        else:
            raise Exception("Unable to connect to interface server")
        print "Connected."

    def send(self, method, params):
        self.interface.send([(method, params)])

    def response(self):
        response = self.interface.get_response()
        return (response.get("method"),
                response.get("params"),
                response.get("result"))

class AddressResolver:

    def __init__(self):
        self.addrs = {}
        self.txs = {}
        self.needed_txs = {}
        self.current_block_height = None
        self.watch_heights = defaultdict(list)

    def set_current_block_height(self, height):
        self.current_block_height = height
        addrs = self.watch_heights[height]:
        del self.watch_heights[height]
        return addrs

    def compute_status(self, address):
        history = self.addrs[address]
        status = ""
        for tx in history:
            tx_hash, tx_height = tx["tx_hash"], tx["height"]
            status += tx_hash + ":%d:" % int(tx_height)
        return hashlib.sha256(status).hexdigest()

    def history_is_required(self, address, status):
        if address not in self.addrs:
            return True
        return self.compute_status(address) != status

    def set_history(self, address, history):
        self.addrs[address] = history
        for item in history:
            tx_hash = item["tx_hash"].decode("hex")
            self.needed_txs[tx_hash] = address

    def transaction(self, tx_hash):
        return self.txs.get(tx_hash)

    def add_transaction(self, tx_hash, tx_body):
        self.txs[tx_hash] = tx_body
        return self.needed_txs.pop(tx_hash, None)

    def received(self, address):
        history = self.addrs[address]
        balances = [0, 0]
        for item in history:
            tx_hash = item["tx_hash"].decode("hex")
            tx_height = item["height"]
            if tx_hash not in self.txs:
                return None
            tx = self.txs[tx_hash]
            is_confirmed = tx_height > 0
            # Could be None on initialisation if block_height is not yet set.
            assert self.current_block_height is not None
            assert self.current_block_height >= tx_height
            number_confirms = self.current_block_height - tx_height
            target_confirms = 2
            if number_confirms < target_confirms:
                # Watch this address
                # First confirmation is already a confirm so minus 1
                target_height = tx_height + target_confirms - 1
                self.watch_heights[target_height].append(address)
            self.check_outputs(tx["outputs"], address, balances, is_confirmed)
        return balances

    def check_outputs(self, outputs, address, balances, is_confirmed):
        for output in outputs:
            if output["address"] != address:
                continue
            if is_confirmed:
                balances[0] += output["value"]
            else:
                balances[1] += output["value"]

def deserialize_tx(tx_hash, tx_height, raw_tx):
    vds = deserialize.BCDataStream()
    vds.write(raw_tx.decode('hex'))
    tx = deserialize.parse_Transaction(vds)
    tx['height'] = tx_height
    tx['tx_hash'] = tx_hash
    return tx

class Application:

    def __init__(self, wallet):
        self.wallet = wallet
        self.resolver = AddressResolver()
        self.interface = Interface()

    def start(self):
        self.interface.start()
        self.interface.send("blockchain.numblocks.subscribe", [])
        self.run()

    def run(self):
        while True:
            self.update()

    def update(self):
        self.update_wallet()
        self.process_response()

    def update_wallet(self):
        latest_id = poll_latest_id()
        addrs = self.wallet.update(latest_id)
        for addr in addrs:
            print "New address: ", addr
            self.interface.send("blockchain.address.subscribe", [addr])
            self.interface.send("blockchain.address.get_history", [addr])

    def process_response(self):
        method, params, result = self.interface.response()
        if method == "blockchain.address.subscribe":
            addr = params[0]
            if self.resolver.history_is_required(addr, result):
                self.interface.send("blockchain.address.get_history", [addr])
        elif method == "blockchain.address.get_history":
            addr = params[0]
            self.resolver.set_history(addr, result)
            # Have we got all the transactions needed
            missing_tx = False
            for item in result:
                if not self.process_history_item(addr, item):
                    missing_tx = True
            if not missing_tx:
                self.compute_balances(addr)
        elif method == "blockchain.transaction.get":
            tx_hash = params[0]
            tx_height = params[1]
            self.process_tx(tx_hash, tx_height, result)
        elif method == "blockchain.numblocks.subscribe":
            addrs = self.resolver.set_current_block_height(result)
            for address in addrs:
                self.compute_balances(address)

    def process_history_item(self, address, item):
        tx_hash = item["tx_hash"]
        tx_height = item["height"]
        if self.resolver.transaction(tx_hash.decode("hex")) is None:
            self.interface.send("blockchain.transaction.get",
                                [tx_hash, tx_height])
            return False
        return True

    def process_tx(self, tx_hash, tx_height, raw_tx):
        tx = deserialize_tx(tx_hash, tx_height, raw_tx)
        address = self.resolver.add_transaction(tx_hash.decode("hex"), tx)
        if address is None:
            return
        self.compute_balances(address)

    def compute_balances(self, address):
        balances = self.resolver.received(address)
        if balances is None:
            return
        self.balance_changed(address, balances)

    def balance_changed(self, address, balances):
        print address, balances

if __name__ == "__main__":
    mpk = "3315ae236373067ea27d92f10f9475b1ff727eebe45f4ce4dd21cf548a237755397548d57fdb94610aef20993b4ff4695cae581d3be98743593336b21090c7d2".decode("hex")
    wallet = Wallet(mpk)
    app = Application(wallet)
    app.start()

