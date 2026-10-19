"""Conservatively preserve explicit synthetic markers through JSON wrappers."""


def known_synthetic(value):
    pending = [value]; found = False; visited = 0
    while pending:
        item = pending.pop(); visited += 1
        if visited > 100000:
            raise ValueError('Synthetic provenance structure exceeds the supported size')
        if isinstance(item, dict):
            for key in ('synthetic', 'synthetic_fixture'):
                if key in item:
                    if type(item[key]) is not bool:
                        raise ValueError('Synthetic marker must be a boolean')
                    found = found or item[key]
            pending.extend(v for v in item.values() if isinstance(v, (dict, list)))
        elif isinstance(item, list):
            pending.extend(v for v in item if isinstance(v, (dict, list)))
    return found
