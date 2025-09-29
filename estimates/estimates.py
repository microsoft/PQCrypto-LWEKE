import operator
from typing import Callable
from sage.all import log, sqrt, pi, RR, ZZ, cached_function  # type: ignore
from frodo import frodo_params
from cost_models import svp_models, reduction_algs, enumeration_models
from lattice_estimator.estimator import LWE, Simulator
from lattice_estimator.estimator.nd import DiscreteGaussian
from lattice_estimator.estimator.lwe_parameters import LWEParameters
from indcca import single_user_cca


def lattice_estimator(name:str, q:int, n:int, m:int, sigma:float, reduction_model:Callable, svp_model:Callable, analysis_type:str, quiet:bool=True):
    rv = OrderedDict()

    secret_distr = DiscreteGaussian(sigma, 0)
    params = LWEParameters(n=n, q=q, Xs=secret_distr, Xe=secret_distr, m=m, tag=f"{name} ct")
    if analysis_type == "beyond":
        if svp_model in enumeration_models:
            deny_list = ("arora-gb", "bkw", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")
            rv["Dual $\\log_2 \\text{cost}$"] = "---"
            rv["Dual $(\\beta_\\text{red}, d)$"] = "---"
            rv["Dual hyb $\\log_2 \\text{red.\ cost}$"] = "---"
            rv["Dual hyb $(\\beta_\\text{red}, \\beta_\\text{sieve}, d)$"] = "---"
        else:
            deny_list = ("arora-gb", "bkw", "bdd_hybrid", "bdd_mitm_hybrid")
        shape = Simulator.CN11
    elif analysis_type == "core":
        deny_list = (
                     "arora-gb", "bkw", "bdd_hybrid", "bdd_mitm_hybrid",
                    #  "dual",        # this is a basic dual attack. it calls DualHybrid internally, but with no secret enumeration/mitm happening, just distinguishing LWE vs uniform
                    #  "dual_hybrid"  # this is MATZOV
                     )
        shape = Simulator.GSA
    else:
        raise ValueError("`analysis_type` can be `\"core\"` or `\"beyond\"`")

    estimate = LWE.estimate(
        params,
        red_cost_model=reduction_model,
        red_shape_model=shape,
        deny_list=deny_list,
        catch_exceptions=False,
        quiet=quiet
    )

    if "usvp" in estimate:
        rv["uSVP $\\log_2 \\text{cost}$"] = "$ %.1f $" % log(estimate["usvp"]["rop"], 2)
        # rv["uSVP beta"] = estimate["usvp"]["beta"]
        # rv["uSVP dim"] = estimate["usvp"]["d"]
        rv["uSVP $(\\beta, d)$"] = "$(%d, %d)$" % (estimate["usvp"]["beta"], estimate["usvp"]["d"])
    if "bdd" in estimate:
        rv["BDD $\\log_2 \\text{cost}$"] = "$ %.1f $" % log(estimate["bdd"]["rop"], 2)
        # rv["BDD red beta"] = estimate["bdd"]["beta"]
        # rv["BDD svp beta"] = estimate["bdd"]["eta"]
        # rv["BDD dim"] = estimate["bdd"]["d"]
        rv["BDD $(\\beta_\\text{red}, \\beta_\\text{svp}, d)$"] = "$(%d, %d, %d)$" % (estimate["bdd"]["beta"], estimate["bdd"]["eta"], estimate["bdd"]["d"])
    if "dual" in estimate:
        # This is the cost of Micciancio-Regev's dual attack against Decision-LWE
        rv["Dual $\\log_2 \\text{cost}$"] = "$ %.1f $" % log(estimate["dual"]["rop"], 2)
        # rv["Dual mem"] = log(estimate["dual"]["mem"], 2)
        # rv["Dual beta"] = estimate["dual"]["beta"]
        # rv["Dual dim"] = estimate["dual"]["d"]
        rv["Dual $(\\beta_\\text{red}, d)$"] = "$(%d, %d)$" % (estimate["dual"]["beta"], estimate["dual"]["d"])
    if "dual_hybrid" in estimate:
        # this is the cost of MATZOV's hybrid dual attack against Search-LWE
        rv["Dual hyb $\\log_2 \\text{red.\ cost}$"] = "$ %.1f $" % log(estimate["dual_hybrid"]["rop"], 2)
        # rv["Dual hyb guess cost"] = log(estimate["dual_hybrid"]["guess"], 2)
        # rv["Dual hyb N"] = log(estimate["dual_hybrid"]["N"], 2)
        # rv["Dual hyb d/s indices"] = estimate["dual_hybrid"]["zeta"]
        # rv["Dual hyb fft indices"] = estimate["dual_hybrid"]["t"]
        # rv["Dual hyb sieve beta"] = estimate["dual_hybrid"]["beta_"]
        # rv["Dual hyb LWE samples"] = estimate["dual_hybrid"]["m"]
        # rv["Dual hyb dim"] = estimate["dual_hybrid"]["m"] + n - estimate["dual_hybrid"]["zeta"] - estimate["dual_hybrid"]["t"]
        rv["Dual hyb $(\\beta_\\text{red}, \\beta_\\text{sieve}, d)$"] = "$(%d, %d, %d)$" % (
            estimate["dual_hybrid"]["beta"],
            estimate["dual_hybrid"]["beta_"],
            estimate["dual_hybrid"]["m"] + n - estimate["dual_hybrid"]["zeta"] - estimate["dual_hybrid"]["t"]
        )
    return rv


from pprint import pprint
from tabulate import tabulate  # type: ignore
from typing import Tuple
import itertools
import parallelism
from collections import OrderedDict


def estimate_attack(estimate_params:Tuple, quiet=True):
    params, svp_model_name, reduction_alg_name, analysis_type = estimate_params
    name = params['name']
    q = params['q']
    n = params['n']
    bar_n = params['bar_n']
    sigma = params['sigma']

    m = n + bar_n
    reduction_model = reduction_algs[reduction_alg_name](svp_models[svp_model_name], svp_model_name)
    estimates = lattice_estimator(name, q, n, m, sigma, reduction_model, svp_models[svp_model_name], analysis_type, quiet=quiet)
    rv = OrderedDict()
    rv["Params"] = name
    rv["SVP model"] = svp_model_name
    rv["Reduction"] = reduction_alg_name
    for (k, v) in estimates.items():
        rv[k] = v
    return rv


def beyond_core_svp():
    data = []
    data_lock = parallelism.Lock()
    beyond_core_analysis = list(itertools.product(
        frodo_params,
        [
            "\\clsfsieve",
            "\\cmemsieve",
            "\\cparaenum"
        ],
        ["\\bkz", "\\pbkz"],
        ["beyond"]
    ))
    total_params = len(beyond_core_analysis)
    for rv in parallelism.eval(estimate_attack, beyond_core_analysis, total=total_params, use_tqdm=True, parallel=False):
        data_lock.acquire()
        try:
            data.append(rv)
        finally:
            data_lock.release()
    data.sort(key = operator.itemgetter('Params', 'Reduction', "uSVP $\\log_2 \\text{cost}$"))
    table = tabulate(data, headers = "keys", tablefmt="latex_raw")
    print("\nBeyond Core SVP\n")
    print(table)


def core_svp():
    data = []
    data_lock = parallelism.Lock()
    core_analysis = list(itertools.product(
        frodo_params,
        [
            "\\qrandwalksieve",
            "\\qgroversieve",
            "\\clsfsieve"
        ],
        ["\\core"],
        ["core"]
    ))
    total_params = len(core_analysis)
    for rv in parallelism.eval(estimate_attack, core_analysis, total=total_params, use_tqdm=True, parallel=True):
        data_lock.acquire()
        try:
            data.append(rv)
        finally:
            data_lock.release()
    data.sort(key = operator.itemgetter('Params', 'Reduction', "uSVP $\\log_2 \\text{cost}$"))
    table = tabulate(data, headers = "keys", tablefmt="latex_raw")
    print("\nCore SVP\n")
    print(table)


def indcca():
    print("\nSingle-pk single-c IND-CCA bit security:")
    for params in frodo_params:
        for model in ["core-loglwe", "beyond-loglwe"]:
            loglwe = params[model]
            print(model)
            single_user_cca(params, loglwe)


if __name__ == "__main__":
    core_svp()
    beyond_core_svp()
    indcca()
