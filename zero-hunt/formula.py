from sympy import Symbol, expand, factor
from sympy.solvers import solve
from pprint import pformat
from operator import add, sub, mul

############# Stuff to handle pretty printing 

class Instruction():
    def __add__(self, other):
        return BinOp(add, self, other)

    def __sub__(self, other):
        return BinOp(sub, self, other)

    def __mul__(self, other):
        return BinOp(mul, self, other)

    def __xor__(self, exp):
        return self**exp

    def __pow__(self, exp):
        if exp != 2:
            raise RuntimeError(f"Only use squarings, exp = { exp }")
        return Sqr(self)
    
class Var(Instruction):
    def __init__(self, name):
        self.name = name
        self.exp = Symbol(name)
        
    def __repr__(self):
        return repr(self.name)

Vars = lambda s: [Var(v) for v in s.split()]
    
class BinOp(Instruction):
    def __init__(self, op, op1, op2):
        self.name = 'tmp'
        self.op = op
        self.op1 = op1
        self.op2 = op2
        self.exp = op(op1.exp, op2.exp)

    def __repr__(self):
        return f"{ self.op1.name } { { add:'+', sub:'-', mul:'*' }[self.op] } { self.op2.name }"

class Sqr(Instruction):
    def __init__(self, op):
        self.name = 'tmp'
        self.op = op
        self.exp = op.exp**2

    def __repr__(self):
        return f"{ self.op.name }^2"

class Formula(dict):
    def __init__(self, vars):
        self.inputs = Vars(vars)
        self.outputs = []
    
    def __setitem__(self, key, val):
        val.name = f't{key}' if isinstance(key, int) else str(key)
        return super().__setitem__(key, val)

    def format_inst(self, inst):
        prompt = '>' if inst in self.outputs else ':'
        return (
            f"{ f'{inst.name}{prompt}': <8}{ inst }\n" +
            ' '*8 + f"{ factor(expand(inst.exp)) }\n" + ' '*10 +
            ('\n' + ' '*10).join(map(pformat, solve(inst.exp)))
            )

    def signature(self):
        return f"{ self.__class__.__name__ }({ ', '.join(x.name for x in self.inputs) })"
    
    def pprint(self):
        '''Print line-by-line algebraic info'''
        return (
            f"/{'*'*10}  { self.__doc__ }  {'*'*10}/\n" +
            f"proc { self.signature() }:\n" +
            "\n\n".join(self.format_inst(v) for v in self.values())
            )

    def __repr__(self):
        '''Print as a straight line program'''
        return (
            f"proc { self.signature() }:\n" +
            "\n".join(f"    { inst.name: <4} <- { inst }" for inst in self.values()) + "\n" +
            "    return " + ', '.join(o.name for o in self.outputs)
        )

    def formula(self, subs=None):
        '''Print as an (affine) formula'''
        if subs is None:
            A = Symbol('A')
            subs = { 'Z':1, 'Z_P':1, 'Z_Q':1, 'Z_QP':1, 'Z₂':1, 'Z₃':1, 'Z₄':1,
                     'C₂₄':1, 'A₂₄⁺':(A+2)/4, 'A₂₄⁻':(A-2)/4}
        return { o.name : factor(expand(o.exp.subs(subs))) for o in self.outputs }
    
############# The formulas
class xDBLADD(Formula):
    '''Combined Doubling and Differential Addition'''
    def __init__(t):
        super().__init__('X_P Z_P X_Q Z_Q X_QP Z_QP A₂₄⁺')
        XP, ZP, XQ, ZQ, XQP, ZQP, Ap = t.inputs
        
        t[0] =  XP + ZP
        t[1] =  XP - ZP
        t[2] =  t[0]^2
        t[3] =  XQ - ZQ
        t[4] =  XQ + ZQ
        t[5] =  t[0] * t[3]
        t[6] =  t[1]^2
        t[7] =  t[1] * t[4]
        t[8] =  t[2] - t[6]
        t['X2'] =  t[2] * t[6]
        t[10] = Ap * t[8]
        t[11] = t[5]-t[7]
        t[12] = t[10]+t[6]
        t[13] = t[5]+t[7]
        t['Z2'] = t[12] * t[8]
        t[15] = t[11]^2
        t[16] = t[13]^2
        t['Z+'] = XQP * t[15]
        t['X+'] = ZQP * t[16]
        t.outputs = (t['X2'], t['Z2'], t['X+'], t['Z+'])

class xDBL(Formula):
    '''Point Doubling'''
    def __init__(t):
        super().__init__('X Z A₂₄⁺ C₂₄')
        Xp, Zp, A24p, C24 = t.inputs
        
        t[0] = Xp - Zp
        t[1] = Xp + Zp
        t[2] = t[0]^2
        t[3] = t[1]^2
        t[4] = C24 * t[2]
        t['X'] =  t[4] * t[3]
        t[6] =  t[3] - t[2]
        t[7] =  A24p * t[6]
        t[8] =  t[4] + t[7]
        t['Z'] =  t[8] * t[6]
        t.outputs = (t['X'], t['Z'])

class xIso2(Formula):
    '''Degree 2 isogeny computation and evaluation'''
    def __init__(t):
        super().__init__('X₂ Z₂ X_P Z_P')
        x, z, XQ, ZQ = t.inputs

        # Computation
        t[0] = x^2
        t['C₂₄'] = z^2
        t['A₂₄⁺'] = t['C₂₄'] - t[0]

        # Evaluation
        t[1] = x + z
        t[2] = x - z
        t[3] = XQ + ZQ
        t[4] = XQ - ZQ
        t[5] = t[1] * t[4]
        t[6] = t[2] * t[3]
        t[7] = t[5] + t[6]
        t[8] = t[5] - t[6]
        t['X'] = XQ * t[7]
        t['Z'] = ZQ * t[8]

        t.outputs = (t['A₂₄⁺'], t['C₂₄'], t['X'], t['Z'])
        
class xIso4(Formula):
    '''Degree 4 isogeny computation and evaluation'''
    def __init__(t):
        super().__init__('X₄ Z₄ X_P Z_P')
        x, z, XQ, ZQ = t.inputs

        # Computation
        t['K₂'] =  x - z
        t['K₃'] =  x + z
        t[0] = z^2
        t[1] = t[0] + t[0]
        t['C₂₄'] = t[1]^2
        t['K₁'] = t[1] + t[1]
        t[2] = x^2
        t[3] = t[2] + t[2]
        t['A₂₄⁺'] = t[3]^2

        # Evaluation
        t[4] = XQ + ZQ
        t[5] = XQ - ZQ
        t[6] = t[4] * t['K₂']
        t[7] = t[5] * t['K₃']
        t[8] = t[4] * t[5]
        t[9] = t[8] * t['K₁']
        t[10] = t[6] + t[7]
        t[11] = t[6] - t[7]
        t[12] = t[10]^2
        t[13] = t[11]^2
        t[14] = t[9] + t[12]
        t[15] = t[13] - t[9]
        t['X'] = t[14] * t[12]
        t['Z'] = t[13] * t[15]

        t.outputs = (t['A₂₄⁺'], t['C₂₄'], t['K₁'], t['K₂'], t['K₃'], t['X'], t['Z'])
        
class xTPL(Formula):
    '''Point Tripling'''
    def __init__(t):
        super().__init__('X Z A₂₄⁺ A₂₄⁻')
        X, Z, Ap, Am = t.inputs
        
        t[0]  =  X - Z 
        t[1]  =  X + Z 
        t[2]  =  t[0]^2 
        t[3]  =  t[1]^2 
        t[4]  =  t[1] + t[0]
        t[5]  =  t[1] - t[0] 
        t[6]  =  t[4]^2 
        t[7]  =  t[6] - t[3]
        t[8]  =  t[7] - t[2]
        t[9]  =  t[3] * Ap 
        t[10]  =  t[9] * t[3]
        t[11]  =  t[2] * Am
        t[12]  =  t[2] * t[11]
        t[13]  =  t[12] - t[10]
        t[14]  =  t[9] - t[11]
        t[15]  =  t[14] * t[8]
        t[16]  =  t[13] + t[15] 
        t[17]  =  t[16]^2 
        t['X']  =  t[17] * t[4] 
        t[19]  =  t[13] - t[15] 
        t[20]  =  t[19]^2 
        t['Z']  =  t[20] * t[5]
        t.outputs = (t['X'], t['Z'])

class xIso3(Formula):
    '''Degree 3 isogeny computation and evaluation'''
    def __init__(t):
        super().__init__('X₃ Z₃ X_P Z_P')
        x, z, XQ, ZQ = t.inputs

        # Computation
        t['K₁'] = x - z
        t[0] = t['K₁']^2
        t['K₂'] = x + z
        t[1] = t['K₂']^2
        t[2] = t[0] + t[1]
        t[3] = t['K₁'] + t['K₂']
        t[4] = t[3]^2
        t[5] = t[4] - t[2]
        t[6] = t[1] + t[5]
        t[7] = t[5] + t[0]
        t[8] = t[7] + t[0]
        t[9] = t[8] + t[8]
        t[10] = t[1] + t[9]
        t['A₂₄⁻'] = t[6] * t[10]
        t[11] = t[1] + t[6]
        t[12] = t[11] + t[11]
        t[13] = t[0] + t[12]
        t['A₂₄⁺'] = t[7] * t[13]

        # Evaluation
        t[14] = XQ + ZQ
        t[15] = XQ - ZQ
        t[16] = t['K₁'] * t[14]
        t[17] = t['K₂'] * t[15]
        t[18] = t[16] + t[17]
        t[19] = t[17] - t[16]
        t[20] = t[18]^2
        t[21] = t[19]^2
        t['X'] = XQ * t[20]
        t['Z'] = ZQ * t[21]

        t.outputs = (t['K₁'], t['K₂'], t['A₂₄⁻'], t['A₂₄⁺'], t['X'], t['Z'])

############# Run automatically
if __name__ == '__main__':
    print(f"""
{ xDBLADD().pprint() }


{ xDBL().pprint() }


{ xIso2().pprint() }


{ xIso4().pprint() }


{ xTPL().pprint() }


{ xIso3().pprint() }
""")
