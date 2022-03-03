
import os
import subprocess
import math
import random


subprocess.call(['make', '-silent', 'clean'])

for p in [434, 503, 610, 751]:
    subprocess.call(['make', '-silent', 'PRIME_SIZE='.strip() + str(p), 'tests'])
    print("!=!=!=!=!=!=!=!=!=!=!=!=!!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")
    print("!=!=!=!=!=!=!=!=!=! PRIME_SIZE=".strip() + str(p).strip() + " !=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")
    print("!=!=!=!=!=!=!=!=!=!=!=!=!=!!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")

    print("\n\n")

    print("!=!=!=!=!=!=!=!=!=!=!=!=!=!!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")
    print("!=!=!=!=!=!=!=!=!=! COUNTERMEASURE OFF !=!=!=!=!=!=!=!=!=!=! ")
    print("!=!=!=!=!=!=!=!=!=!=!=!=!=!=!!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")

    subprocess.call(['./sike'.strip() + str(p).strip() + '/test_SIKE'])
    subprocess.call(['./sidh'.strip() + str(p).strip() + '/test_SIDH'])

    subprocess.call(['make', '-silent', 'clean'])
    subprocess.call(['make', '-silent', 'PRIME_SIZE='.strip() + str(p), 'tests', 'COUNTERMEASURE=YES'])
    
    print("\n\n")
    print("!=!=!=!=!=!=!=!=!=!=!=!=!=!=!!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")
    print("!=!=!=!=!=!=!=!=!=!=! COUNTERMEASURE ON !=!=!=!=!=!=!=!=!=! ")
    print("!=!=!=!=!=!=!=!=!=!=!=!=!=!=!=!!=!=!=!=!=!=!=!=!=!=!=!=!=!=! ")

    subprocess.call(['./sike'.strip() + str(p).strip() + '/test_SIKE'])
    subprocess.call(['./sidh'.strip() + str(p).strip() + '/test_SIDH'])

    subprocess.call(['make', '-silent', 'clean'])

    print("\n\n")