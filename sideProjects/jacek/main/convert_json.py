import json
import os


def get_filenames(path):
    filenames = os.listdir(path)
    temp = []
    for f in filenames:
        if f[0] == ".":
            continue
        temp.append((path + "/" + f, f))
    return temp

def to_json(file_path, filename):
    data = []
    print("Processing: %s" % file_path)
    with open(file_path) as data_file:
        for line in data_file:
            data.append(line)
    filename = filename.replace(".txt", "")
    with open(filename+".json", 'w') as outfile:
        json.dump(data, outfile)

if __name__ == '__main__':
    PATH = "/Users/daniel/Desktop/sideProjects/jacek/new_censys/FormatGZ.GZ"
    filenames = get_filenames(path=PATH)
    print(filenames)
    for f in filenames:
        to_json(f[0], "json_data2/"+f[1])
        os.remove(f[0])