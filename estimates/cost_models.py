from sage.all import ZZ, RR, log, ceil, floor  # type: ignore
from sage.all import cached_function  # type: ignore
from lattice_estimator.estimator.reduction import ReductionCost, Kyber


@cached_function
def QSieveRandomWalk(beta):
    # https://eprint.iacr.org/2021/570
    _beta = beta - Kyber.d4f(beta)
    return _beta * ZZ(2)**RR(0.257*_beta)


@cached_function
def QSieveGrover(beta):
    # https://research.tue.nl/files/14673128/20160216_Laarhoven.pdf
    _beta = beta - Kyber.d4f(beta)
    return _beta * ZZ(2)**RR(0.265*_beta)


@cached_function
def CSieveLSF(beta):
    # BDGL16 https://eprint.iacr.org/2015/1128
    _beta = beta - Kyber.d4f(beta)
    return _beta * ZZ(2)**RR(0.292*_beta)


@cached_function
def CSieve2DRAM(beta):
    # table 4 of [Jaques24] https://cic.iacr.org/p/1/3/6
    _beta = beta - Kyber.d4f(beta)
    return _beta * ZZ(2)**RR(0.3113*_beta)


@cached_function
def CParallelABLR21(beta):
    # this below returns the simulated wall-time for one approx SVP call
    # including requried preprocessing for asymptotically optimal enumeration.
    # being wall-time, we don't include the _beta factor used for sieving.
    # to account for parallelisation, we estimate the memory used by sieving,
    # and estimate the amount of CPUs that a machine equivalent to the one used
    # for sieving would run under a constant cpu : memory : wire ratio assumption [Jaques24]
    # assuming an nVidia GeForce RTX 4090 architecture
    log_runtime = RR(0.1250 * beta * log(beta, 2) - 0.654 * beta + 25.84 + log(64, 2))
    # available memory: compare to sieving w/ d4f enabled
    _beta = beta - Kyber.d4f(beta)
    log_sieving_mem = RR(0.2075 * _beta + log(_beta, 2)) # sieving needs storing enough rank-_beta vectors
    log_mem_to_cpu_ratio = 28.3
    log_cpu = log_sieving_mem - log_mem_to_cpu_ratio
    cost = ZZ(2) ** (log_runtime - log_cpu)
    return cost


svp_models = {
    "\\qrandwalksieve": QSieveRandomWalk,
    "\\qgroversieve": QSieveGrover,
    "\\clsfsieve": CSieveLSF,
    "\\cmemsieve": CSieve2DRAM,
    "\\cparaenum": CParallelABLR21
}


enumeration_models = [
    CParallelABLR21
]


class CoreSieve(ReductionCost):
    d4f = lambda self, beta: Kyber.d4f(beta)

    def __init__(self, svp_model, svp_model_name="?"):
        self.__name__ = f"core-{svp_model_name}"
        self.svp_model = svp_model
        # overwrite short_vectors function
        if svp_model in enumeration_models:
            # NOTE: self.short_vectors only matters when evaluating dual attacks
            self.short_vectors = self.short_vectors_simple
        else:
            self.short_vectors = self.short_vectors_core_svp_balanced

    def short_vectors_core_svp_balanced(self, beta, d, N=None, B=None, preprocess=True, sieve_dim=None):
        """
        NOTE: This function is modelled after `Kyber.short_vectors` in the lattice-estimator.
        This function is called while estimating the dual and MATZOV attacks.
        It assumes that a sieve returns many short vectors of length sqrt(4/3) longer than the shortest
        vector in the lattice.
        Since in MATZOV the lattice reduction and short-vector sieving phases use different block sizes,
        beta_1 and beta_2, these have to be chosen as to balance the two phases.
        In Frodo's analysis, we choose to consider the dual and MATZOV's attacks only in the Core-SVP
        model, where BKZ costs a single call to sieving, using the dimensions-for-free trick.
        This means that we must chose beta_1 = beta_2 = d4f(BKZ's block size).

        Cost of outputting many somewhat short vectors using BKZ-β.

        The output of this function is a tuple of four values:

        - `ρ` is a scaling factor. The output vectors are expected to be longer than the shortest
          vector expected from an SVP oracle by this factor.
        - `c` is the cost of outputting `N` vectors
        - `N` the number of vectors output, which may be larger than the value put in for `N`.
        - `β'` the cost parameter associated with sampling

        This is using an observation insprired by [AC:GuoJoh21]_ that we can run a sieve on the
        first block of the basis with negligible overhead.

        :param beta: Cost parameter (≈ SVP dimension).
        :param d: Lattice dimension.
        :param N: Number of vectors requested.
        :param preprocess: Include the cost of preprocessing the basis with BKZ-β.
               If ``False`` we assume the basis is already BKZ-β reduced.
        :return: ``(ρ, c, N, β')``

        """
        beta_ = beta - floor(self.d4f(beta))

        assert sieve_dim in [None, beta_]
        if sieve_dim == None:
            sieve_dim = beta_

        if N == 1:
            if preprocess:
                return 1.0, self(beta, d, B=B), 1, sieve_dim
            else:
                return 1.0, 1, 1, sieve_dim
        elif N is None:
            N = floor(2 ** (0.2075 * sieve_dim))

        c = N / floor(2 ** (0.2075 * sieve_dim))
        return 1.1547, ceil(c) * self(beta, d), ceil(c) * floor(2 ** (0.2075 * sieve_dim)), sieve_dim

    def __call__(self, beta, d, B=None):
        return self.svp_model(beta)



class BKZModel(CoreSieve):

    d4f = lambda self, beta: Kyber.d4f(beta)

    def __init__(self, svp_model, svp_model_name="?", tours=8):
        self.__name__ = f"bkz-{svp_model_name}"
        self.svp_model = svp_model
        # overwrite short_vectors function
        if svp_model in enumeration_models:
            # NOTE: self.short_vectors only matters when evaluating dual attacks
            self.short_vectors = self.short_vectors_simple
        else:
            self.short_vectors = self.short_vectors_core_svp_balanced
        self.tours = tours
    
    def __call__(self, beta, d, B=None):
        # we conservatively ignore the last beta indices
        if d == beta:
            svp_calls_per_tour = 1
        else:
            svp_calls_per_tour = d - beta
        one_tour = svp_calls_per_tour * self.svp_model(beta)
        return self.tours * one_tour


class PBKZModel(CoreSieve):

    def __init__(self, svp_model, svp_model_name="?"):
        self.__name__ = f"pbkz-{svp_model_name}"
        self.svp_model = svp_model
        # overwrite short_vectors function
        if svp_model in enumeration_models:
            # NOTE: self.short_vectors only matters when evaluating dual attacks
            self.short_vectors = self.short_vectors_simple
        else:
            self.short_vectors = self.short_vectors_core_svp_balanced

    def __call__(self, beta, d, B=None):
        # we conservatively ignore the last beta indices on each BKZ tour
        return sum(
            (1 if d == _beta else d - _beta) * self.svp_model(_beta)
            for _beta in range(60, beta+1)
        )

reduction_algs = {
    '\\core': CoreSieve,
    '\\bkz': BKZModel,
    '\\pbkz': PBKZModel
}
