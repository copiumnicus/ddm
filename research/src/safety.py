from collections import defaultdict
from dataclasses import dataclass, asdict
import plotly.express as px
import pandas as pd


# have to model what is the safe unclaimed amount to hold given on chain state

class Vendor():
    def __init__(self, addy):
        self.addy = addy
    
    def derive(self, v):
        return self.addy+str(v)

class ChainState:
    def __init__(self):
        self.client_subs = {}
        self.client_balance = defaultdict(float)
    
    def sub(self, vendor: Vendor, client):
        if client not in self.client_subs:
            self.client_subs[client] = []
        self.client_subs[client].append(vendor)
    
    def deposit(self, client, amt):
        self.client_balance[client] += float(amt)
    
    def exposure(self, client) -> int:
        return 0 if client not in self.client_subs else len(self.client_subs[client])


@dataclass
class UnclaimedRisk:
    subs: float
    unclaimed_per_vendor: float
    unclaimed_per_vendor_safe: float

    def __str__(self):
        return "subs={} unclaimed/vendor={:.2f} unclaimed_safe/vendor={:2f}".format(self.subs, self.unclaimed_per_vendor, self.unclaimed_per_vendor_safe)

# the clients are bound by on chain contract to be able to subscribe at max 1 sub per x sec
CLIENT_ALLOWED_SUB_RATE_PER_SEC = 2
# we essentialy model the next risk*sub_rate seconds of client aggresively subscribing and expanding
VENDOR_CLIENT_EXPAND_RISK = 5

def calc_unclaim_risk(total_subs, client_balance) -> UnclaimedRisk:
    # for every sub, the client could have unclaimed balance there
    # all vendors know this and divide the balance equally assuming the client spent everything already
    # the longer vendors hold out on settling the bigger the risk thus they should settle when their 
    # unclaimed bal approaches unspent_per_vendor
    unspent_per_vendor = client_balance / total_subs
    # now if we divide simply by the subs, the unclaimed risk is still there
    # because the client could subscribe to more we have to account for that
    # if the client would start subscribing to new vendors at it's max sub rate
    unspent_per_vendor_safe = client_balance / (total_subs + VENDOR_CLIENT_EXPAND_RISK)
    return UnclaimedRisk(total_subs, unspent_per_vendor, unspent_per_vendor_safe)

# > you are a vendor
# > you want to know if the client is solvent
# > you don't want to provide services for checks that don't clear
# 
# - what is the safe total balance per client you can hold?
def unclaim_risk(args):
    cs = ChainState()
    a = "alice" # alice is a menace
    deposit = args.deposit
    cs.deposit(a, deposit) # alice deposits 10$
    v = Vendor("bob")

    rs = []
    for i in range(100):
        cs.sub(v.derive(i), a)
        client_exposure = cs.exposure(a)
        print(f"client_exp={client_exposure}")
        r = calc_unclaim_risk(client_exposure, cs.client_balance[a])
        rs.append(r)
        print(f"{r}")

    df = pd.DataFrame([asdict(r) for r in rs])
    f = px.line(df, x="subs", y=["unclaimed_per_vendor", "unclaimed_per_vendor_safe"], title=f"Vendor safe unclaimed on client_deposit=${deposit}")
    f.show()

if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser()
    parser.add_argument("-ur", help="Show unclaim risk plot", action=argparse.BooleanOptionalAction)
    parser.add_argument("--deposit", help="Alice deposit", default=10)
    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)

    args = parser.parse_args()
    if args.ur:
        unclaim_risk(args)

