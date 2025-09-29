from math import exp, log
from frodo import frodo_params


def delta(n, log_delta_1):
    assert n == 1
    return 2**log_delta_1


def advcca_ub(n, bar_n, bar_m, qro, nc, nu, log_M, Ls, log_delta_1, loglwe, RD, alpha, lensalt, lmbd):
    s = 2 * n * bar_n + 2 * bar_m * n + bar_m * bar_n
    M = 2**log_M
    advcpa_nc_nu = (bar_n + bar_m) / 2**loglwe
    t_lb = 2**32

    return t_lb, \
    2 * (
        (
            (
                6 * qro / M
                + 2**(-lmbd) / t_lb
                + nc / M / t_lb
                + qro * delta(nu, log_delta_1)
                + 2 * advcpa_nc_nu
            )
            * exp(s * RD)
        )**(1-1/alpha)
        + delta(nu, log_delta_1) / t_lb
        + qro / M
        + nu * nc * (nc - 1) / M / 2**(lensalt) / t_lb
    )


def single_user_cca(params, loglwe):
    nc = nu = Ls = 1
    name = params["name"]
    n = params["n"]
    bar_n = params["bar_n"]
    bar_m = params["bar_m"]
    log_M = params["log_M"]
    log_delta_1 = params["log_delta_1"]
    lensalt = params["lensalt"]
    RD = params["RD"]
    alpha = params["alpha"]
    qro = params["qro"]
    eps = params["lmbd"]

    t_lb, adv_ub = advcca_ub(n, bar_n, bar_m, qro, nc, nu, log_M, Ls, log_delta_1, loglwe, RD, alpha, lensalt, eps)
    print(name, log(adv_ub, 2), f"for t > 2^{log(t_lb, 2)}")


if __name__ == "__main__":
    for params in frodo_params:
        loglwe = params["core-loglwe"]
        single_user_cca(params, loglwe)

    print()
    print("Manual evaluation of \\FrodoLOne in C.1.1:", log(2 * ((( (2**-15 + 2**-32) / 2**128 + 2**(-512-32) + 2**-18 * 2**-138.7  + 2 * 2**-134.5     )  * exp(20544 * 0.0000324)  )**0.995 + 2**-32 * 2**-138.7 + 2**-18/2**128), 2), "for t > 2^32")
