import re

_RC_RE = re.compile('-rc(\d+)$')

def _split(ver_str):
    # Split off any '-rc' part; split rest at dots; map to integers
    match = _RC_RE.search(ver_str)
    if match:
        ver_str = ver_str[:match.start()]
        rc_n = int(match.group(1))
    else:
        rc_n = None
    return [int(comp) for comp in ver_str.split('.')], rc_n

def get_sort_key(ver_str):
    # Treat x -rc y as (x-1), (large), y so it sorts between x-1 stable updates
    # and x
    ver_comp, rc_n = _split(ver_str)
    if rc_n is not None:
        ver_comp[-1] -= 1
        ver_comp.append(1000000)
        ver_comp.append(rc_n)
    return ver_comp
