import json
import os

FILENAMES = [
     ("/Users/daniel/Desktop/sideProjects/jacek/timestampjson20190306000000000001",
     "timestampjson20190306000000000001")
]


def to_json(file_path, filename):
    data = []

    with open(file_path) as data_file:
        for line in data_file:
            data.append(line)
    filename = filename.replace(".txt", "")
    with open(filename+".json", 'w') as outfile:
        json.dump(data, outfile)

if __name__ == '__main__':

    for f in FILENAMES:
        to_json(f[0], f[1])
        os.remove(f[0])