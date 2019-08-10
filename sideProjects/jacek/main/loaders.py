import base64
import json
import csv
import config as config
import datetime
import time
import os


def load_scan(file_path):
    """

    :param file_path: path to a json file
    :return: object with loaded json data
    """
    with open(file_path) as json_file:
        data = json.load(json_file)
        return data


def load_mirai_ips_filter_date_port(path_to_mirai,
                                    date_limit="2018-12-04T00:00:00Z",
                                    seen="fseen",
                                    filter_port=False,
                                    filter_date=False):
    """
    This method loads data from mirai csv file into memory.
    Different combinations of port and date filter can applied
    according to the parameters listed below.

    :param path_to_mirai absolute path to csv
    :param date_limit: string in format %Y-%m-%dT%H:%M:%SZ
    :param seen: fseen or lseen
    :param filter_port: Boolean, if filter by port 23/2323
    :param filter_date: Boolean, if True read after date_limit
    :return: set of ips
    """
    ips = set()
    start_date = time.mktime(datetime.datetime.strptime(date_limit, "%Y-%m-%dT%H:%M:%SZ").timetuple())
    _INDEX = config.FSEEN
    if seen == "lseen":
        _INDEX = config.LSEEN

    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        # Checks
        if not isinstance(row[0], str):
            raise ValueError('Not a string: %s' % row[0])
        if " " in row[0]:
            raise ValueError("IP contains Whitespace %s" % row[0])

        if len(row[0]) > 2:  # apply different matching filter below
            if not filter_date:
                if not filter_port:
                    ips.add(row[0])
                else:
                    if int(row[3]) == 23 or int(row[3]) == 2323:
                        ips.add(row[0])
            else:  # Use only rows after some point at time
                noted_on = time.mktime(datetime.datetime.strptime(row[_INDEX], "%Y-%m-%dT%H:%M:%SZ").timetuple())
                if noted_on >= start_date:
                    if not filter_port:  # Do not filter ports
                        ips.add(row[0])
                    else:
                        if int(row[3]) == 23 or int(row[3]) == 2323:  # filter ports
                            ips.add(row[0])

    return ips


def load_censys_ips(dir_path, version=2):
    """

    :param dir_path:
    :param version: new data files
    :return: set of unique ids from censys files
    """
    ips = set()  # stores elements without repetitions
    ips_with_banner = set()
    ips_no_banner = set()
    ips_banners = dict()
    total_others = 0
    files = os.listdir(dir_path)  # list all files from the directory
    old_size = 0
    for _file in files:
        print("processing file: ", _file)
        data = load_scan(dir_path + "/" + _file)
        print("Number of lines in the file: ", len(data))
        for d in data:
            d = json.loads(d)
            if version == 2:
                temp_ports = [int(p) for p in d['ports']]
                if 23 not in temp_ports and 2323 not in temp_ports:
                    total_others += 1  # we dont store them in set, this count may contain duplicates
                    continue  # not using port 23 or 2323 -> skip it
            if not isinstance(d['ip'], str):
                raise ValueError('Not a string: %s' % d['ip'])
            if " " in d['ip']:
                raise ValueError("IP contains Whitespace %s" %d['ip'])
            # passed the checks, add to the set
            ips.add(d['ip'])

            try:
                if len(d['banner']) > 0:
                    ips_banners[d['ip']] = d['banner']
                    ips_with_banner.add(d['ip'])
                else:
                    ips_no_banner.add(d['ip'])
            except KeyError as ke:
                continue
        print("Added %d ips from this file" % (len(ips) - old_size))
        old_size = len(ips)

    return ips, ips_with_banner, ips_no_banner, ips_banners, total_others


def export_counters(outfile_base_name, _counter, counter_name):
    """

    :param outfile_base_name:
    :param _counter:
    :param counter_name:
    :return:
    """
    outfile = open(outfile_base_name + "_" + counter_name + ".csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')
    for key, value in _counter.most_common():
        out_writer.writerow([key, value])
    print("Exported counters: %s" % counter_name)


def export_banners(outfile_base_name, banners_map, counter_name, version=2):
    """

    :param outfile_base_name:
    :param banners_map:
    :param counter_name:
    :param version: old (1) or new (2) censys data
    :return:
    """
    outfile = open(outfile_base_name + "_" + counter_name + ".csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')

    # iterate over sorted map
    for key, value in sorted(banners_map.items(), key=lambda e: -(len(e[1]))):
        if version == 1:
            out_writer.writerow([base64.b64decode(key)] + [len(value)] + value)
        else:
            out_writer.writerow([key] + [len(value)] + value)
    print("Exported [banners --> IP_list] map.")


def export_general(outfile_base_name, mappigns, mapping_name):
    """

    :param outfile_base_name:
    :param mappigns:
    :param dict_name:
    :return:
    """
    outfile = open(outfile_base_name + "_" + mapping_name + ".csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')

    # iterate over sorted map
    for key, value in sorted(mappigns.items(), key=lambda e: -(len(e[1]))):
        out_writer.writerow([key] + [len(value)] + value)

    print("Exported [%s] map." % mapping_name)