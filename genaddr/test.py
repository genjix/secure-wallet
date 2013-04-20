from _genaddr import pubkey_to_address, DeterministicWallet
wallet = DeterministicWallet()
mpk = "3315ae236373067ea27d92f10f9475b1ff727eebe45f4ce4dd21cf548a237755397548d57fdb94610aef20993b4ff4695cae581d3be98743593336b21090c7d2".decode("hex")
wallet.set_master_public_key(mpk)
print pubkey_to_address(wallet.generate_public_key(0))

