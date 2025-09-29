# All matrices are defined over Z_q

# Attacking the long-term secret key:
# LWE instance = (A, B), S, E
# A is n x n, uniform
# S is n x \bar{n}, sampled close to round(N(0, sigma^2))
# E is n x \bar{n}, sampled close to round(N(0, sigma^2))
# breaking a single column breaks Decision LWE, so we can ignore \bar{n}

# Attacking the ephemeral secret in a ciphertext
# LWE instance = ([A|B]^T, [C1|C2]^T), S'^T, [E'|E'']^T
# [A|B]^T = (n + \bar{n}) x n
# S'^T is n x \bar{m}, sampled close to round(N(0, sigma^2))
# [E'|E'']^T is (n + \bar{n}) x \bar{m} sampled close to round(N(0, sigma^2))
# breaking a single column breaks Decision LWE, so we can ignore \bar{m}


frodo_params = [
    {
        'name': "\\FrodoLOne",
        'n': 640,
        'bar_n': 8,
        'bar_m': 8,
        'q': 32768,
        'sigma': 2.8,
        'log_M': 128,
        'log_delta_1': -138.7,
        'lensalt': 2*128,
        'RD': 0.0000324,
        'alpha': 200,
        'qro': 2**(-18),
        'lmbd': 512,
        'core-loglwe': 138.5,  # core-SVP, obtained from `sage estimates.py`
        'beyond-loglwe': 149.8,  # beyond-core-SVP, obtained from `sage estimates.py`
    },
    {
        'name': "\\FrodoLThree",
        'n': 976,
        'bar_n': 8,
        'bar_m': 8,
        'q': 65536,
        'sigma': 2.3,
        'log_M': 192,
        'log_delta_1': -199.6,
        'lensalt': 2*192,
        'RD': 0.0000140,
        'alpha': 500,
        'qro': 2**(-18),
        'lmbd': 512,
        'core-loglwe': 199.8,  # core-SVP, obtained from `sage estimates.py`
        'beyond-loglwe': 212.6,  # beyond-core-SVP, obtained from `sage estimates.py`
    },
    {
        'name': "\\FrodoLFive",
        'n': 1344,
        'bar_n': 8,
        'bar_m': 8,
        'q': 65536,
        'sigma': 1.4,
        'log_M': 256,
        'log_delta_1': -252.5,
        'lensalt': 2*256,
        'RD': 0.0000264,
        'alpha': 1000,
        'qro': 2**(-18),
        'lmbd': 512,
        'core-loglwe': 254.8,  # core-SVP, obtained from `sage estimates.py`
        'beyond-loglwe': 266.8,  # beyond-core-SVP, obtained from `sage estimates.py`
    }
]