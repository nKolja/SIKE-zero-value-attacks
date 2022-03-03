from setup import chipwhisperersetup

# Path to SIKE compiled code
PLATFORM = 'CWLITEARM'

fw_path = f"../../chipwhisperer/hardware/victims/firmware/simpleserial-jinv-sikep434/simpleserial-jinv-sikep434-{PLATFORM}.hex"

# Connects to chipwhisperer
(target, scope) = chipwhisperersetup(fw_path, PLATFORM)

# Captures traces
from capture import CW_launch_jinv
traces_cat = {}
(_, traces_cat['0']) = CW_launch_jinv(target, scope, N_traces=1000, zero=True)
(_, traces_cat['1']) = CW_launch_jinv(target, scope, N_traces=1000, zero=False)

target.dis()
scope.dis()

# Processes traces
from statistics import mean
tr_avg = {}
tr_avg['1'] = [mean(l) for l in map(list, zip(*traces_cat['1']))]
tr_avg['0'] = [mean(l) for l in map(list, zip(*traces_cat['0']))]

dom = [pair[0] - pair[1] for pair in zip(tr_avg['1'], tr_avg['0'])]

# Plots (picture will be placed under "../figs")
from makeplot import wide_plot_size, tall_plot_size, dom_vs_traces_plot
wide_plot_size()
tall_plot_size()

dom_vs_traces_plot(tr_avg['1'], tr_avg['0'], dom)

from utils import write_all_traces
write_all_traces(traces_cat['0'], name='traces_jinv_zero_CW')
write_all_traces(traces_cat['1'], name='traces_jinv_nonzero_CW')
#trace_cat['0'] = read_all_traces('../data/traces_jinv_zero_CW_1000x24400.txt')
#trace_cat['1'] = read_all_traces('../data/traces_jinv_nonzero_CW_1000x24400.txt')