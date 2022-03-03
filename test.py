
import os
import subprocess
import math
import random


def numberToBase(n, b):
    if(b == 16):
        return hex(n)[2:]
    if n == 0:
        return '0'
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    digits = [str(a) for a in digits][::-1]
    return ''.join(digits)


def attack_bob_j(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./bob_computation', 'j',  str(secret_key_bits),  padded_key]
    guessed_bits = ""
    for k in range(bits_i_can_extract):
        subprocess.run(['./malicious_alice', str(k), guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_j', 'public_keys/alice_pk'])
        bit = subprocess.check_output(['./bob_computation', 'j',  str(secret_key_bits),  padded_key, str(k)])
        guessed_bits += bit.decode()

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the isogeny by analyzing j-invariant, target uses", 3 ,"isogenies")
    print("Secret key:\t", print_key[:-bits_i_can_extract],"+", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", print_guess[:-bits_i_can_extract], "+", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()


def attack_bob_O_0(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./bob_computation', 'O',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_z', str(k) , guessed_bits])
        subprocess.call(['mv', 'public_keys/pk_z_0', 'public_keys/alice_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += bit.decode()

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_O_0")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()

def attack_bob_O_1(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./bob_computation', 'O',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_z', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_z_1', 'public_keys/alice_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += str(1-int(bit.decode()))

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_O_1")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()


def attack_bob_T_0(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./bob_computation', 'T',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_x', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_x_0', 'public_keys/alice_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += bit.decode()

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_T_0")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()

def attack_bob_T_1(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./bob_computation', 'T',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_x', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_x_1', 'public_keys/alice_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += str(1-int(bit.decode()))

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_T_1")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()




def attack_alice_j(prime_size, secret_key_bits, secret_key_trits, trits_i_can_extract, bad_point_exponent, print_base):
    is_odd_order = "2 and " if(prime_size == 610) else ""

    secret_key = random.getrandbits(secret_key_bits)
    secret_key = int(secret_key)
    key_trits = numberToBase(secret_key, 3).zfill(secret_key_trits)
    key_trits = key_trits[::-1]
    computing_party_command = ['./alice_computation',  'j',  str(secret_key_trits),  key_trits]

    guessed_trits = ""

    for k in range(trits_i_can_extract):
        subprocess.call(['./malicious_bob', str(k) , guessed_trits])
        subprocess.call(['mv', 'public_keys/pk_j', 'public_keys/bob_pk'])
        trit = subprocess.check_output(computing_party_command).decode()
        if(trit == '0'):
            guessed_trits += '0'
        else:
            subprocess.call(['mv', 'public_keys/pk_j_1', 'public_keys/bob_pk'])
            trit = subprocess.check_output(computing_party_command).decode()
            if(trit == '0'):
                guessed_trits += '1'
            else:
                guessed_trits += '2'       

    print_key = key_trits[secret_key_trits - 1::-1]
    print_guess = guessed_trits[::-1].rjust(secret_key_trits, '*')

    print("Attack on the isogeny by analyzing j-invariant, target uses " + is_odd_order + "4 isogenies")
    print("Secret key:\t", print_key[:-trits_i_can_extract], "+" if trits_i_can_extract < secret_key_trits else "", numberToBase(int(print_key[-trits_i_can_extract:], 3), print_base))
    print("Guessed key:\t", print_guess[:-trits_i_can_extract], "+" if trits_i_can_extract < secret_key_trits else "", numberToBase(int(print_guess[-trits_i_can_extract:], 3), print_base))
    print("First", trits_i_can_extract, "trits of secret key are correctly guessed:", (key_trits[:len(guessed_trits)]) == (guessed_trits[:]))
    print()


def attack_alice_O_0(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):
    is_odd_order = "2 and " if(prime_size == 610) else ""

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./alice_computation', 'O',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_z', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_z_0', 'public_keys/bob_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += bit.decode()

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_O_0")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()

def attack_alice_O_1(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):
    is_odd_order = "2 and " if(prime_size == 610) else ""

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./alice_computation', 'O',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_z', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_z_1', 'public_keys/bob_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += str(1-int(bit.decode()))

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_O_1")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()


def attack_alice_T_0(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):
    is_odd_order = "2 and " if(prime_size == 610) else ""

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./alice_computation', 'T',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_x', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_x_0', 'public_keys/bob_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += bit.decode()

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_T_0")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()

def attack_alice_T_1(prime_size, secret_key_bits, bits_i_can_extract, bad_point_exponent, print_base):
    is_odd_order = "2 and " if(prime_size == 610) else ""

    secret_key = random.getrandbits(secret_key_bits)
    padded_key = bin(secret_key)[2:].zfill(secret_key_bits)
    padded_key = padded_key[::-1]
    computing_party_command = ['./alice_computation', 'T',  str(secret_key_bits),  padded_key]
    guessed_bits = ""

    for k in range(bits_i_can_extract):
        subprocess.call(['./malicious_pk_x', str(k) , guessed_bits])
        subprocess.run(['mv', 'public_keys/pk_x_1', 'public_keys/bob_pk'])
        bit = subprocess.check_output(computing_party_command + [str(k)])
        guessed_bits += str(1-int(bit.decode()))

    print_key = padded_key[secret_key_bits - 1::-1]
    print_guess = guessed_bits[::-1].rjust(secret_key_bits, '*')

    print("Attack on the three-point ladder with pk_T_1")
    print("Secret key:\t", numberToBase(int(print_key[-bits_i_can_extract:],2), print_base).upper())
    print("Guessed key:\t", numberToBase(int(print_guess[-bits_i_can_extract:],2), print_base).upper())
    print("First", bits_i_can_extract, "bits of secret key are correctly guessed:", (padded_key[:len(guessed_bits)]) == (guessed_bits[:]))
    print()




























prime_sizes  = [434, 503, 610, 751]

isog_order_3 = [137, 159, 192, 239]
isog_order_2 = [108, 125, 152, 186]
isog_order   = [isog_order_2, isog_order_3]

sk_bits_b       = [217, 252, 304, 378]
can_extract_b   = [208, 244, 299, 365]

sk_bits_a       = [216, 250, 305, 372]
sk_trits_a      = [137, 158, 193, 235]
can_extract_a   = [135, 156, 187, 235]

sk_bits         = [sk_bits_b, sk_bits_a]            # How many bits I can extract
can_extract     = [can_extract_b, can_extract_a]    # How many trits I can extract

bad_point_exp_2 = [9, 7, 7, 8]
bad_point_exp_3 = [3, 4, 2, 5]

bad_point_exp   = [bad_point_exp_2, bad_point_exp_3]

os.system("make clean -silent")
pretty_print = True
# pretty_print = False

for prime_index in range(4):
    ps = prime_sizes[prime_index]
    makefile = "make -silent PRIME_SIZE=".strip() + str(ps).strip() + " attacks"
    os.system(makefile)
    print("\n==================  PRIME SIZE =", ps, "BITS ==================")
    print("------------------  TARGET IS BOB  -------------------------")

    skb = sk_bits[0][prime_index]
    ceb = can_extract[0][prime_index] 
    bpe = bad_point_exp[0][prime_index]
    pb1 = 16 if pretty_print else 2
    attack_bob_j(ps, skb, ceb, bpe, pb1)
    attack_bob_O_0(ps, skb, skb, bpe, pb1)
    attack_bob_O_1(ps, skb, skb, bpe, pb1)
    attack_bob_T_0(ps, skb, skb, bpe, pb1)
    attack_bob_T_1(ps, skb, skb, bpe, pb1)

    print("\n-----------------  TARGET IS ALICE  ------------------------")

    skb = sk_bits[1][prime_index]
    skt = sk_trits_a[prime_index]
    cea = can_extract[1][prime_index]
    bpe = bad_point_exp[1][prime_index]
    pb2 = 9 if pretty_print else 3
    attack_alice_j(ps, skb, skt, cea, bpe, pb2)
    attack_alice_O_0(ps, skb, skb, bpe, pb1)
    attack_alice_O_1(ps, skb, skb, bpe, pb1)
    attack_alice_T_0(ps, skb, skb, bpe, pb1)
    attack_alice_T_1(ps, skb, skb, bpe, pb1)

    os.system("make clean -silent")









