import os
import numpy as np

def read_all_traces(traces_file):
    assert os.path.isfile(traces_file), f"Error: {traces_file} is not an existing file"
    return np.loadtxt(traces_file)

def write_all_traces(all_traces, dir="../data/", name="traces", start=0, end=None):
    assert os.path.isdir(dir), f"Error: {dir} is not an existing directory"
    if end:
        assert start < end, f"Error: invalid range: [{start}:{end}]"
    end = min(end, len(all_traces[0])) if end else len(all_traces[0])
    filename = os.path.join(dir, f"{name}_{len(all_traces)}x{end-start}.txt")
    np.savetxt(filename, [t[start:end] for t in all_traces], delimiter=" ", header="", footer="", comments="", encoding="latin1")
