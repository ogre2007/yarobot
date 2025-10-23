import gzip
import os

import orjson as json

from app.config import DB_PATH


def load(filename, just_json=False):
    if just_json:
        with open(filename, "rb") as file:
            return json.loads(file.read())
    else:
        file = gzip.GzipFile(filename, "rb")
        object = json.loads(file.read())
        file.close()
        return object


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def save(object, filename):
    path = os.path.join(DB_PATH, filename)
    with open(path, "wb") as file:
        file.write(bytes(json.dumps(object)))


def load_db(file, local_counter, just_json=False):
    filePath = os.path.join(DB_PATH, file)
    print("[+] Loading %s ..." % filePath)
    before = len(local_counter)
    js = load(get_abs_path(filePath), just_json)
    local_counter.update(js)
    added = len(local_counter) - before
    print("[+] Total: %s / Added %d entries" % (len(local_counter), added))

    return len(local_counter)
