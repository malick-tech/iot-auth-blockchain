import os

import algokit_utils

algorand = algokit_utils.AlgorandClient.default_localnet()
dispenser = algorand.account.localnet_dispenser()

print("Adresse    :", dispenser.address)
if os.getenv("PRINT_PRIVATE_KEY", "").lower() == "true":
    print("Cle privee :", dispenser.private_key)
else:
    print("Cle privee : masquee (definir PRINT_PRIVATE_KEY=true pour l'afficher en local)")
