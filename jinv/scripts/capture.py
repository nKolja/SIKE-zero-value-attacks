import time
import random

### CAPTURE SCRIPT ###
def CW_launch_jinv(target, scope, N_traces=1, zero=False):
    SEED = "Born to blossom, bloom to perish"
    PTLEN = 220

    # Total number of samples
    scope.adc.samples = 24400

    ### START ACQUISITION ###
    plaintexts = []
    traces = []
    random.seed(SEED)
    for i in range(N_traces):
        # Generate random plaintext
        if zero:
            pt = 0
        else:
            pt = random.randint(0, 2**(PTLEN*8)-1)
        pt = int.to_bytes(pt, byteorder="big", length=PTLEN)

        # Arm oscilloscope
        scope.arm()
        target.flush()

        # Capture
        target.simpleserial_write('p', pt)
        time.sleep(0.1)
        ret = scope.capture()
        if ret:
            print('Timeout happened during acquisition')
            continue

        # Clear buffer (if any)
        num_char = target.in_waiting()
        rd = ""
        while num_char > 0:
            rd += target.read(timeout=10)
            time.sleep(0.01)
            num_char = target.in_waiting()

        # Save text + trace
        plaintexts += [pt]
        traces += [scope.get_last_trace()]

        # Print progress
        if i % max(N_traces//10, 1) == 0:
            print(f"Captured {i}/{N_traces}...")

    # Finished
    print(f"Captured {N_traces}/{N_traces}...")

    return (plaintexts, traces)