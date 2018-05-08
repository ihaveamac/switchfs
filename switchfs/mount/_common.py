from functools import wraps

# TODO: take ArgumentParser and fuse opts parse from fuse-3ds


def ensure_lower_path(method):
    @wraps(method)
    def wrapper(self, path, *args, **kwargs):
        return method(self, path.lower(), *args, **kwargs)
    return wrapper
