from copy import copy
from multiprocessing import cpu_count, Pool

from polypyus.models import Hash

binary_hash = []


def initializer(hash_values):
    global binary_hash
    binary_hash = hash_values


def matcher(targets, theta=None):
    likelihood = 0.0
    l = len(targets)
    max_id_ = l - 1

    best_pos = 0
    best_likelihood = 0.0
    last_match = 0
    defaults = list(range(min(4, max_id_ + 1)))
    next_expected = copy(defaults)
    if theta is None:
        theta = 1 / l
    for pos, value in binary_hash:
        for i, e in enumerate(next_expected):
            if targets[e] == value:
                l_step = 1
                # last_match += 1
                next_expected[i] = (e + 1) % l
                break
        else:
            l_step = 0
            if last_match > 0:
                max_expected = max(next_expected)
                if max_expected < max_id_:
                    next_expected.append(max_expected + 1)
                last_match -= 1
            else:
                next_expected = copy(defaults)
        likelihood = likelihood * (1 - theta) + theta * l_step
        if likelihood >= best_likelihood:
            best_pos = pos
            best_likelihood = likelihood
    return best_pos, best_likelihood


def exact_mactcher(targets):
    l = len(targets)
    theta = 1 / l
    best_l = 0
    best_p = 0
    best_size = 0
    i = 0
    last_pos = 0
    size = 0

    for pos, value in binary_hash:
        i = i % l
        if targets[i] == value:
            i += 1
        else:
            i = i - 1 if i > 0 else 0
        if i > 0:
            size += pos - last_pos
        else:
            size = 0
        last_pos = pos

        likelihood = i / l
        if likelihood >= best_l:
            best_l = likelihood
            best_p = pos
            best_size = size
    return best_p, best_l, best_size


def matcher_pool(hashes, targets, matcher_fnc=matcher):

    with Pool(cpu_count() - 1, initializer, [hashes]) as pool:
        return pool.map(matcher_fnc, (t.values for t in targets))
