import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt

#import seaborn as sns
from statistics import mean
import datetime

#sns.set()

def tall_plot_size():
    matplotlib.rcParams['figure.figsize'] = (matplotlib.rcParams['figure.figsize'][0], 7.68)

def wide_plot_size():
    matplotlib.rcParams['figure.figsize'] = (10.24, matplotlib.rcParams['figure.figsize'][1])

def regular_plot_size():
    matplotlib.rcParams['figure.figsize'] = (6.4, 4.80)

def tr_plot(trace, xlabel="Sample [Pt]", ylabel="Power Consumption [V]"):
    fig = plt.figure()
    if type(trace[0]) is int:
        coeff = 1
    else:
        coeff = 1
    plt.plot([coeff*s for s in trace])
    plt.grid(True)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    #plt.show()
    filename = datetime.datetime.now().strftime("../figs/tr_plot_%Y-%m-%d_%H-%M-%S.png")
    plt.savefig(filename)
    plt.clf()

def avg_tr_plot(tab, xlabel="Sample [Pt]", ylabel="Power Consumption [V]", title="Average Power Consumption"):
    fig = plt.figure()
    if type(tab[0][0]) is int:
        coeff = 1.0/1000
    else:
        coeff = 1.0/1000
    plt.plot([coeff*mean(l) for l in map(list, zip(*tab))])
    plt.grid(True)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.ticklabel_format(style="sci")
    plt.tight_layout()
    #plt.show()
    filename = datetime.datetime.now().strftime("../figs/avg_tr_plot_%Y-%m-%d_%H-%M-%S.png")
    plt.savefig(filename)
    plt.clf()

def dom_vs_traces_plot(tr_avg0, tr_avg1, dom, title="Difference of means locations", poi=None, fit=False):
    fig = plt.figure()
    plt.subplot(2, 1, 1)
    plt.title(title)
    plt.plot(tr_avg0)
    plt.plot(tr_avg1)
    plt.grid(True)
    plt.xlabel("Sample [Pt]")
    plt.ylabel("V")
    plt.subplot(2, 1, 2)
    plt.plot(dom, color='green')
    if poi:
        for p in poi:
            plt.plot(p, dom[p], 'ro')
    if not fit:
        ytop = max(max(dom)+0.0001, 0.0002)
        ybot = min(min(dom)-0.0001, -0.0002)
        plt.ylim(ybot, ytop)
    plt.grid(True)
    plt.xlabel("Sample [Pt]")
    plt.ylabel("DoM")
    plt.tight_layout()
    #plt.show()
    filename = datetime.datetime.now().strftime("../figs/dom_vs_traces_plot_%Y-%m-%d_%H-%M-%S.png")
    plt.savefig(filename)
    plt.clf()
