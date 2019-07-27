import base64
import csv
import datetime
import json
import os
import time
from collections import Counter


JSON_DATA_DIR = "/Users/daniel/Desktop/sideProjects/jacek/json_data"

MIRAI_PATH = "/Users/daniel/Desktop/sideProjects/jacek/mirai_enriched_2018_07_03_2019.csv"


def load_scan(file_path):
    """

    :param file_path: path to a json file
    :return: object with loaded json data
    """
    with open(file_path) as json_file:
        data = json.load(json_file)
        return data


def load_mirai_ips_filter_date_port(path_to_mirai,
                                    date_limit="2019-03-04T00:00:00Z",
                                    seen="fseen",
                                    filter_port=False,
                                    filter_date=False):
    """

    :param path_to_mirai absolute path to csv
    :param date_limit: string in format %Y-%m-%dT%H:%M:%SZ
    :param seen: fseen or lseen
    :param filter_port: Boolean, if filter by port 23/2323
    :param filter_date: Boolean, if True read after date_limit
    :return: set of ips
    """
    ips = set()
    start_date = time.mktime(datetime.datetime.strptime(date_limit, "%Y-%m-%dT%H:%M:%SZ").timetuple())
    _INDEX = 7
    if seen == "lseen":
        _INDEX = 8

    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        # Checks
        if not isinstance(row[0], str):
            print('Not a string!!!', row[0])
            break
        if " " in row[0]:
            print("Whitespace", row[0])
            break

        if len(row[0]) > 2:  # apply different matching filter below
            if not filter_date:
                if not filter_port:
                    ips.add(row[0])
                else:
                    if int(row[3]) == 23 or int(row[3]) == 2323:
                        ips.add(row[0])
            else:
                noted_on = time.mktime(datetime.datetime.strptime(row[_INDEX], "%Y-%m-%dT%H:%M:%SZ").timetuple())
                if noted_on >= start_date:
                    if not filter_port:
                        ips.add(row[0])
                    else:
                        if int(row[3]) == 23 or int(row[3]) == 2323:
                            ips.add(row[0])

    return ips


def load_censys_ips(dir_path):
    """

    :param dir_path:
    :return: set of unique ids from censys files
    """
    ips = set()
    ips_banners = dict()
    files = os.listdir(dir_path)
    old_size = 0
    for _file in files:
        print("processing file: ", _file)
        data = load_scan(dir_path + "/" + _file)
        print("Number of lines in the file: ", len(data))
        for d in data:
            d = json.loads(d)
            if not isinstance(d['ip'], str):
                print('Not a string!!!', d['ip'])
                break
            if " " in d['ip']:
                print("Whitespace", d['ip'])
                break
            ips.add(d['ip'])
            try:
                if len(base64.b64decode(d['banner'])) > 0:
                    ips_banners[d['ip']] = d['banner']
            except KeyError as ke:
                continue
        print("Added %d ips from this file" % (len(ips) - old_size))
        old_size = len(ips)
    return ips, ips_banners

"""
def load_censys_ips_with_banners(dir_path):
    \"""

    :param dir_path: path to dir with censys json data
    :return: Returns a dictionary in form of dict["someIP"] = "some banner"
    \"""
    ips = dict()
    files = os.listdir(dir_path)
    old_size = 0
    for _file in files:
        print("processing file: ", _file)
        data = load_scan(dir_path + "/" + _file)
        print("Number of lines in the file: ", len(data))
        for d in data:
            d = json.loads(d)
            if not isinstance(d['ip'], str):
                print('Not a string!!!', d['ip'])
                break
            if " " in d['ip']:
                print("Whitespace", d['ip'])
                break
            try:
                if len(base64.b64decode(d['banner'])) > 0:
                    ips[d['ip']] = d['banner']
            except KeyError as ke:
                continue
        print("Added %d ip-banner pair from this file" % (len(ips) - old_size))
        old_size = len(ips)
    return ips
"""

def get_stats_helper(data):
    """

    :param data: object with loaded json data
    :return:  count of devices with port 23 or 2323 using telnet protocol,
                count of devices with not empty banners
                count of devices with empty banners
    """
    # Using sets therefore no duplicates possible by definition
    _telnet_23 = set()
    _banners = set()
    _banners_empty = set()

    for d in data:
        d = json.loads(d)
        if (int(d['port_number']) == 23 or int(d['port_number']) == 2323) and d['protocol'] == 'telnet':
            _telnet_23.add(d['ip'])
        try:
            if len(base64.b64decode(d['banner'])) > 0:
                _banners.add(d['ip'])
            else:
                _banners_empty.add(d['ip'])
        except KeyError as ke:
            _banners_empty.add(d['ip'])

    return _telnet_23, _banners, _banners_empty


def count_telnet23_banner(dir_path):
    """
    Gets global number of devices with telnet and protocol 23
    :param dir_path:
    :return:
    """
    telnet_23 = set()
    banners = set()
    banners_empty = set()

    files = os.listdir(dir_path)
    files = list(filter(lambda x: x.split(".")[1] == "json", files))

    for _file in files:
        print("processing file: ", _file)
        data = load_scan(dir_path + "/" + _file)
        _telnet_23, _banners, _banners_empty = get_stats_helper(data)
        telnet_23 = telnet_23.union(_telnet_23)
        banners = banners.union(_banners)
        banners_empty = banners_empty.union(_banners_empty)

    return telnet_23, banners, banners_empty


def get_counts(infected_ips, path_to_mirai, prefix_count, country_count):
    """
    Count infected ips by country and prefix
    :param infected_ips: set of ips
    :param path_to_mirai: absolute path to csv
    :return:
    """
    COUNTRY = 15
    PREFIX = 17
    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        if len(row[0]) > 2:
            if row[0] in infected_ips:
                prefix_count[row[PREFIX]] += 1
                country_count[row[COUNTRY]] += 1
                # remove from the set to not count twice
                infected_ips.remove(row[0])
    print("Counting done. ")
    return prefix_count, country_count


def count_asn(infected_ips, path_to_mirai, asn_counter):
    ASN = 10
    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        if len(row[0]) > 2:
            if row[0] in infected_ips:
                asn_counter[row[ASN]] += 1
                # remove from the set to not count twice
                infected_ips.remove(row[0])
    print("Counting done. ")
    return asn_counter


def count_ports(infected_ips, path_to_mirai, port_count):
    PORT = 3
    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        if len(row[0]) > 2:
            if row[0] in infected_ips:
                port_count[row[PORT]] += 1
                # remove from the set to not count twice
                infected_ips.remove(row[0])
    print("Counting done. ")
    return port_count


def group_by_banners(infected_ips, banner_map):
    """

    :param infected_ips:
    :return: a dictionary in form of dict[banner] = [list of ips with that banner]
    """
    #banner_map = load_censys_ips_with_banners(JSON_DATA_DIR)
    result = dict()
    i = 0
    try:
        for key, value in banner_map.items():
            i += 1
            if key in infected_ips:
                if value in result:
                    result[value].append(key)
                else:
                    result[value] = [key]
    except ValueError as ve:
        print(i, "\t", ve)
        i += 1

    return result


def match_mirai_censys(_mirai_ips, _censys_ips):
    """

    :param _mirai_ips: set
    :param _censys_ips: set
    :return: intersection of two sets => infected ips
    """

    return _censys_ips.intersection(_mirai_ips)


def infected_banners_stats(infected, empty_banners):
    """
    Performs set intersection operation to find common elements
    :param infected: set of unique infected ips
    :param empty_banners: set of ips with empty banners from censys
    :return: number of infected devices with banners and without banners
    """
    count_infected = len(infected)
    count_empty_banners = len(infected.intersection(empty_banners))
    count_not_empty = count_infected - count_empty_banners

    return count_not_empty, count_empty_banners


def prepare_censys_data():
    _censys_ips, _ips_banners = load_censys_ips(JSON_DATA_DIR)
    censys_telnet23, censys_with_banners, censys_empty_banners = count_telnet23_banner(JSON_DATA_DIR)

    return _censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,_ips_banners


def generate_report(censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,
                    path_to_mirai, _date_limit="2019-03-04T00:00:00Z",
                    _seen="fseen", _filter_port=False, _filter_date=False, outfile_base_name="output"):
    """

    :param censys_ips: set of all censys ips
    :param censys_telnet23: set of ips with port 23/2323
    :param censys_with_banners: set of censys ips with banners
    :param censys_empty_banners: set of censys ips without banners
    :param path_to_mirai:
    :param _date_limit: the oldest date to look for
    :param _seen: fseen or lseen used for filtering, fseen is default
    :param _filter_port: Boolean (if function should filter mirai by port)
    :param _filter_date: Boolean (if function should filter mirai by date_limit)
    :param outfile_base_name: base name of output file used for exports
    :return: void
    """
    print("\n################## Processing " + outfile_base_name + " ##################")
    if _filter_port:
        print("Filtering by ports 23 and 2323")
    if _filter_date:
        print("Filtering by date, retrieving records starting from " + _date_limit)
    print() #empty line

    prefix_count = Counter()
    country_count = Counter()

    mirai_ips = load_mirai_ips_filter_date_port(
        path_to_mirai,
        date_limit=_date_limit,
        seen=_seen,
        filter_port=_filter_port,
        filter_date=_filter_date)
    print("Loaded %d IPs from MIRAI." % len(mirai_ips))

    infected = match_mirai_censys(mirai_ips, censys_ips)
    prefix_count, country_count = get_counts(infected.copy(), path_to_mirai, prefix_count, country_count)
    banners_count_not_empty, count_empty_banners = infected_banners_stats(infected, censys_empty_banners)

    print("Infected total: ", len(infected))
    print("Infected with banners", banners_count_not_empty)
    print("Infected without banners", count_empty_banners)

    ########################## Export infected IPs ###############################################
    outfile = open(outfile_base_name + "_infected.csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')

    out_writer.writerow(["Infected total",len(infected)])
    out_writer.writerow(["Infected with banners", banners_count_not_empty])
    out_writer.writerow(["Infected without banners", count_empty_banners])
    for inf in infected:
        out_writer.writerow([inf])

    ########################## Export Counters ###############################################
    export_counters(outfile_base_name, prefix_count, "prefix_count")
    export_counters(outfile_base_name, country_count, "country_count")

    print("\n################# Prefix top 10 #########################")
    for key, value in prefix_count.most_common(10):
        print(key, "\t", value)

    print("\n################# Prefix top 10 #########################")
    for key, value in country_count.most_common(10):
        print(key, "\t", value)


def export_counters(outfile_base_name, _counter, counter_name):
    outfile = open(outfile_base_name + "_" + counter_name + ".csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')
    for key, value in _counter.most_common():
        out_writer.writerow([key, value])


if __name__ == '__main__':
    # get all censys info

    censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,\
        _banners_map = prepare_censys_data()
    print("Censys IPs: ", len(censys_ips))

    print("Censys telnet+port23/2323 IPs: ", len(censys_telnet23))
    print("Censys with banners: ", len(censys_with_banners))
    print("Censys without banners: ", len(censys_empty_banners))
    generate_report(censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,
                    MIRAI_PATH, _date_limit="2019-03-04T00:00:00Z",
                    _seen="fseen", _filter_port=False, _filter_date=False, outfile_base_name="results/all/all")
    

    generate_report(censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,
                    MIRAI_PATH, _date_limit="2019-03-04T00:00:00Z",
                    _seen="fseen", _filter_port=True, _filter_date=False,
                    outfile_base_name="results/port23_only/port23")
    generate_report(censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,
                    MIRAI_PATH, _date_limit="2019-03-04T00:00:00Z",
                    _seen="fseen", _filter_port=False, _filter_date=True,
                    outfile_base_name="results/past04_only/past04")
    generate_report(censys_ips, censys_telnet23, censys_with_banners, censys_empty_banners,
                    MIRAI_PATH, _date_limit="2019-03-04T00:00:00Z",
                    _seen="fseen", _filter_port=True, _filter_date=True,
                    outfile_base_name="results/port23_past04_only/port23_past04")

    ########################## Export ASN, PORT, BANNERS ##########################################
    mirai_ips = load_mirai_ips_filter_date_port(
        MIRAI_PATH,
        filter_port=True)
    print("Loaded %d IPs from MIRAI." % len(mirai_ips))

    asn_counter = Counter()
    port_counter = Counter()

    _infected = match_mirai_censys(mirai_ips, censys_ips)

    asn_count = count_asn(_infected.copy(), MIRAI_PATH, asn_counter)
    port_count = count_ports(_infected.copy(), MIRAI_PATH, port_counter)

    export_counters("results/port23_only/asn.csv", asn_count, "asn_count")
    export_counters("results/port23_only/ports.csv", port_count, "port_count")

    print("\n################# ASN top 10 #########################")
    for key, value in asn_count.most_common(10):
        print(key, "\t", value)

    print("\n################# PORT top 10 #########################")
    for key, value in port_count.most_common(10):
        print(key, "\t", value)

    out_banners_map = group_by_banners(_infected, _banners_map)
    outfile = open("results/port23_only/banner_groups.csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')
    for key, value in sorted(out_banners_map.items(), key=lambda e: -(len(e[1]))):
        out_writer.writerow([key, base64.b64decode(key)] + [len(value)] + value)



