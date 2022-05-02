#!/usr/bin/env python3

import matplotlib.pyplot as plt
import numpy as np

if __name__ == '__main__':
    input_file = 'rssi.txt'
    counts = 1000

    X = [i + 1 for i in range(counts)]
    Y = []

    with open(input_file, 'r') as f:
        for i in range(counts):
            Y.append(int(f.readline()))

    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    ax.set_title('RSSI of sta owl0')
    ax.set_xlabel('times get_station called')
    ax.set_ylabel('dBm')

    ax.plot(X, Y)

    plt.show()
    