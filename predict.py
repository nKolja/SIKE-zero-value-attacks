#!/usr/bin/env python

from random import randint

def predict(strat, order, isodeg=3, mul=1, evals=None, step=1, inf=None, zout=None):
    if evals is None:
        evals = []
    if not len(strat):
        if mul == 0 and inf is None:
            inf = step
        return zout, inf, step + 1, [0 if mul == e or order and mul + e % order == 0 else e for e in evals]
    n = strat[0]
    assert n > 0 and n <= len(strat)
    L = strat[1:len(strat)-n+1]
    R = strat[len(strat)-n+1:]
    if order:
        nmul = mul * isodeg**n % order
    else:
        nmul = mul * randint(1,10**10)
    if inf and zout is None:
        zout = step
    zout, inf, step, es = predict(L, order, isodeg, nmul, [mul] + evals, step, inf, zout)
    return predict(R, None, isodeg, es[0], es[1:], step, inf, zout)

print("# 3-isogenies")

S3 = (66,33,17,9,5,3,2,1,1,1,1,2,1,1,1,4,2,1,1,1,2,1,1,8,4,2,1,1,1,2,1,1,4,2,1,1,
      2,1,1,16,8,4,2,1,1,1,2,1,1,4,2,1,1,2,1,1,8,4,2,1,1,2,1,1,4,2,1,1,2,1,1,32,
      16,8,4,3,1,1,1,1,2,1,1,4,2,1,1,2,1,1,8,4,2,1,1,2,1,1,4,2,1,1,2,1,1,16,8,4,
      2,1,1,2,1,1,4,2,1,1,2,1,1,8,4,2,1,1,2,1,1,4,2,1,1,2,1,1)

print("\n".join([str((i, predict(S3, 2**i))) for i in range(1,20)]))

print("\n# 4-isogenies")

S2 = (48,28,16,8,4,2,1,1,2,1,1,4,2,1,1,2,1,1,8,4,2,1,1,2,1,1,4,2,1,1,2,1,1,13,
      7,4,2,1,1,2,1,1,3,2,1,1,1,1,5,4,2,1,1,2,1,1,2,1,1,1,21,12,7,4,2,1,1,2,1,
      1,3,2,1,1,1,1,5,3,2,1,1,1,1,2,1,1,1,9,5,3,2,1,1,1,1,2,1,1,1,4,2,1,1,1,2,
      1,1)

print("\n".join([str((i, predict(S3, 3**i, 4))) for i in range(1,20)]))
