from random import random
import pandas as pd
from countmin import CountMinSketch

depths = [2,3,4,5,6,7,8,9,10]
widths = [500,1000,2000,5000,10000,15000,20000]

top_k = 100

data = pd.read_pickle('dataset10M.pkl')

print("pickle read done")

list_vals = []
val_hash = {}
for index, row in data.iterrows():
    val = row['src']+"|"+row['dst']+"|"+str(int(row['sport']))+"|"+str(int(row['dport']))+"|"+str(int(row['proto']))
    list_vals.append(val)
    if val in val_hash:
        val_hash[val]=val_hash[val]+1
    else:
        val_hash[val]=1

correct_list = []
for key,val in val_hash.items():
    correct_list.append([key,val])

#TODO : make a plot that shows the depth needed for each width to approach 100% accuracy, or width needed for each depth to reach 100% accuracy

correct_list.sort(key=lambda x: x[1], reverse=True)
print(len(correct_list))
print("correct list evaluated")

for depth in depths:
    seeds = [int(random()*10000) for x in range(depth)]
    for width in widths:
        cm = CountMinSketch(width, depth, seeds)
        cur_set = set()
        for val in list_vals:
            cm.increment(val)
            cur_set.add(val)
        
        cur_approx_list = []
        for key in cur_set:
            cur_approx_list.append([key,cm.estimate(key)])
        cur_approx_list.sort(key=lambda x: x[1], reverse=True)

        #calculate accuracy of top 100 hitters
        incorrect=0
        for i in range(top_k):
            if cur_approx_list[i]!=correct_list[i]:
                incorrect+=1
        
        print(depth, width, "accuracy ", ((top_k-incorrect)/top_k)*100, "%")
