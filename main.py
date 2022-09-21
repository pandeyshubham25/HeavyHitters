from random import random
import pandas as pd
from countmin import CountMinSketch

depths = [2, 3, 4, 5, 6, 7, 8, 9, 10]
widths = [500, 1000, 2000, 5000, 10000, 15000, 20000]
top_k = 100

# Read dataset
data = pd.read_pickle('dataset_0.pkl')
print("pickle read done")

# Iterate through dataset and find unique flows and their packet count
flow_packet_count = {}

for index, row in data.iterrows():
    flow_key = row['src'] + "|" + row['dst'] + "|" + str(int(row['sport'])) + "|" + str(int(row['dport'])) + "|" + str(int(row['proto']))
    if flow_key not in flow_packet_count:
        flow_packet_count[flow_key] = 1
    else:
        flow_packet_count[flow_key] += 1
print(f"Flow calculations done. Found {len(flow_packet_count)} flows!")

# Finding reverse sorted list of flows for finding top k heavy hitters
actual_heavy_hitters = []
for key, val in flow_packet_count.items():
    actual_heavy_hitters.append([key, val])

actual_heavy_hitters.sort(key=lambda x: x[1], reverse=True)
print("Actual Heavy Hitters calculated")

# TODO : make a plot that shows the depth needed for each width to approach 100% accuracy, or width needed for each depth to reach 100% accuracy

for depth in depths:
    # Random seeds are used to initialize the "width" hash functions so we effectively get different hashes for the same flow
    seeds = [int(random()*10000) for x in range(depth)]
    for width in widths:
        cm = CountMinSketch(width, depth, seeds)

        # Simulate CM Sketch counting
        for flow, flow_count in flow_packet_count.items():
            for i in range(0, flow_count):
                cm.increment(flow)

        # Get estimate of the heavy hitters from CM Sketch
        cms_heavy_hitters = []
        for flow, flow_count in flow_packet_count.items():
            cms_heavy_hitters.append([flow, cm.estimate(flow)])
        
        # Reverse sorting list of flows for finding top k heavy hitters
        cms_heavy_hitters.sort(key=lambda x: x[1], reverse=True)

        # calculate accuracy of top 100 hitters
        incorrect = 0
        for i in range(top_k):
            if cms_heavy_hitters[i] != actual_heavy_hitters[i]:
                incorrect += 1

        print(depth, width, "accuracy ", ((top_k-incorrect)/top_k)*100, "%")
