"""
Wrapper interface to parallelise experiments.

To run, use the following pattern:

def fun(params=(x, y)): function to run
def instance_gen(params): for x in ...: for y in ...: yield (x, y)

res = 0
lock = Lock
for rv in eval(fun, instance_gen(params)):
    if rv['res'] better than res:
        lock.acquire()
        try:
            res = rv['res']
        finally:
            lock.release()
res # best result

"""


import multiprocessing
from typing import Callable, Union, Iterable
from tqdm import tqdm  # type: ignore
from settings import NPROC # type: ignore


def single_core_eval(
    fun: Callable,
    inputs: Iterable,
    total: Union[float,None]=None,
    use_tqdm: bool=False
):
    if use_tqdm:
        for _input in tqdm(inputs, total=total):
            yield fun(_input)
    else:
        for _input in inputs:
            yield fun(_input)


def multi_core_eval(
    fun: Callable,
    inputs: Iterable,
    total: Union[float,None]=None,
    use_tqdm: bool=False,
    cores: int=0,
    batch_size: Union[int, None]=1
):
    pool_size = NPROC
    if cores > 0 and cores < NPROC:
        pool_size = cores

    with multiprocessing.Pool(pool_size) as pool:
        if use_tqdm:
            generator = tqdm(pool.imap_unordered(fun, inputs, batch_size), total=total)
        else:
            generator = pool.imap_unordered(fun, inputs, batch_size)

        for rv in generator:
            yield rv


def eval(
    fun: Callable,
    inputs: Iterable,
    total: Union[float,None]=None,
    use_tqdm: bool=False,
    parallel: bool=True,
    cores: int=0,
    batch_size: Union[int, None]=1
):
    if parallel:
        generator = multi_core_eval(fun, inputs, total, use_tqdm, cores, batch_size)
    else:
        generator = single_core_eval(fun, inputs, total, use_tqdm)

    for evaluation in generator:
        yield evaluation


Lock = multiprocessing.Lock
