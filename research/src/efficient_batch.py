import plotly.express as px
import pandas as pd

# https://arbiscan.io/tx/0x323321b6f3953817b707b4060759203ac5a7c0f44fe3aca6441dd22c1d4667db
# proof verification costs $0.009235
# what is the first efficient batch size?
BATCH_SIZE = [2**i for i in range(1,9)]
MIN_PAY_SIZE = 0.5 / 100 # half cent
PROOF_COST = 0.9235 / 100

if __name__ == "__main__":
    print(BATCH_SIZE)
    res = []
    for size in BATCH_SIZE:
        min_val = MIN_PAY_SIZE * size
        res.append({
            "size": size,
            "proof_frac_of_val": PROOF_COST / min_val
        })


    df = pd.DataFrame(res)
    fig = px.line(df, x="size", y="proof_frac_of_val")
    fig.show()

    # settlement only becomes kinda efficient at size>=64 where proof cost is 2.8%
    # and goes down to 0.7% at size 256

    # In current configuration it means that the vendor could cash in at size 64.
    # Size 64 at min pay size of 0.5 cent gives us 32 cents settlement
    # Quicknode subscription is 42$/month so thats $1.4/day.
    # That would mean that vendors could cash-in at 2.8% loss 4.37 times a day per client
    # (assuming they actually use them:), hate subscriptions)
    # Cash in at 1.4% loss 2.18 times a day. And at 0.7% loss 1.05 times a day.
    # Those values are pretty good since they are worst case. The protocol on top might use
    # bigger micropayments like 1 cent to ensure efficiency of communication for highly used vendors.

    # Let's assume a quicknode user who actually uses all of quicknodes credits. At 0.5 cent min tx
    # the client would sign 280 micropayments per day which is 1 every 5 minutes
    # Now let's imagine some crazy $900 per month case like the solana geyser.
    # The client would have to sign a half cent micropayment every 20 seconds.
    # That enters an area where sudden surge in requests to vendor might block the client.
    # We don't want the client to be blocked, the experience needs to be seamless.
    # So in this case we might sign 2 cent micropayments to increase the window to 80 seconds.


