#Setup the chipwhisprerer.

import time
import chipwhisperer as cw

def chipwhisperersetup(fw_path, PLATFORM='CWLITEARM'):
    # Try to connect to chipwhisperer
    try:
        scope = cw.scope()
        target = cw.target(scope)
    except IOError:
        print("INFO: Caught exception on reconnecting to target - attempting to reconnect to scope first.")
        print("INFO: This is a work-around when USB has died without Python knowing. Ignore errors above this line.")
        scope = cw.scope()
        target = cw.target(scope)

    print("INFO: Found ChipWhisperer😍")

    if "STM" in PLATFORM or PLATFORM == "CWLITEARM" or PLATFORM == "CWNANO":
        prog = cw.programmers.STM32FProgrammer
    elif PLATFORM == "CW303" or PLATFORM == "CWLITEXMEGA":
        prog = cw.programmers.XMEGAProgrammer
    else:
        prog = None

    time.sleep(0.05)
    scope.default_setup()

    # Flash code on card
    cw.program_target(scope, prog, fw_path)

    # The maximum number of samples is hardware-dependent: - cwlite: 24400 - cw1200: 96000
    # Note: can be reconfigured afterwards
    if PLATFORM == "CWNANO":
        scope.adc.samples = 800
    else:
        scope.adc.samples = 2000

    # Prints whatever card sends
    print(target.read())

    return (target, scope)

def reset_target(scope):
    scope.io.nrst = 'low'
    time.sleep(0.05)
    scope.io.nrst = 'high'
    time.sleep(0.05)

def simpleserial(target, cmd, x):
    target.simpleserial_write(cmd, x)
    time.sleep(1)
    res = target.read()
    print(f"\'{cmd}\' response: (len={len(res)}): {res.encode('latin-1') if len(res) > 0 else '-'}")
    return res
