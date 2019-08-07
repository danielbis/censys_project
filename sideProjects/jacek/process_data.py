import base64
import csv
import datetime
import json
import os
import time
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt

JSON_DATA_DIR = "/Users/daniel/Desktop/sideProjects/jacek/json_data2"

MIRAI_PATH = "/Users/daniel/Desktop/sideProjects/jacek/mirai_enriched_2018_07_03_2019.csv"
# indices
PREFIX = 17
COUNTRY = 15
ASN = 10
FSEEN = 7
LSEEN = 8
DST_PORT = 3


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
    _INDEX = FSEEN
    if seen == "lseen":
        _INDEX = LSEEN

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


def get_counts(infected_ips, path_to_mirai, filter_by_port=False):
    """
    Count infected ips by country, prefix and asn
    :param infected_ips: set of ips
    :param path_to_mirai: absolute path to csv
    :param filter_by_port: if true only rows with port 23 and 2323 are counted
    :return: prefix_count, country_count, asn_count of type dict
    """
    prefix_count = Counter()
    country_count = Counter()
    asn_count = Counter()

    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        if filter_by_port and int(row[DST_PORT]) != 23 and int(row[DST_PORT]) != 2323:
            continue  # skip this row, we don't care about this port
        if len(row[0]) > 2:
            if row[0] in infected_ips:
                prefix_count[row[PREFIX]] += 1
                country_count[row[COUNTRY]] += 1
                asn_count[row[ASN]] += 1
                # remove from the set to not count twice
                infected_ips.remove(row[0])
    print("Counting prefixes, countries and asn numbers done. ")

    return prefix_count, country_count, asn_count


def group_by(path_to_mirai, outfile, _censys_ips, by=ASN):
    """
    Match ip to different ASNs or Countries where they appeared
    :param path_to_mirai:
    :param outfile: path to output file
    :param _censys_ips: infected ips matched between censys and miari
    :param by: group by ASN or Country of origin
    :return: void (exports to a csv)
    """
    mappings = dict()

    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        # Checks
        if not isinstance(row[0], str):
            raise ValueError('Not a string: %s' % row[0])
        if " " in row[0]:
            raise ValueError("IP contains Whitespace %s" % row[0])

        if row[0] in _censys_ips:
            if row[0] in mappings:
                mappings[row[0]].add(row[by])
            else:
                mappings[row[0]] = set()
                mappings[row[0]].add(row[by])

    outfile = open(outfile, "w")
    out_writer = csv.writer(outfile, dialect='excel')
    for key, value in sorted(mappings.items(), key=lambda e: -(len(e[1]))):
        out_writer.writerow([key] + list(value))


def count_ports(infected_ips, path_to_mirai):
    """
    Gets stats in form of port_number => total of unique infected ips
    :param infected_ips: list of infected ips from censys
    :param path_to_mirai:
    :return: dict()
    """
    port_count = dict()
    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        if len(row[0]) > 2:
            if row[0] in infected_ips:
                port_count[row[DST_PORT]] += 1
                # remove from the set to not count twice
                infected_ips.remove(row[0])
    print("Counting done. ")
    return port_count


def group_by_banners(infected_ips, banner_map):
    """

    :param infected_ips:
    :param banner_map
    :return: a dictionary in form of dict[banner] = [list of ips with that banner]
    """
    #banner_map = load_censys_ips_with_banners(JSON_DATA_DIR)
    result = dict()
    i = 0
    try:
        for key, value in banner_map.items():
            if key in infected_ips:
                if value in result:
                    result[value].append(key)
                else:
                    result[value] = [key]
            i += 1
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


def plot_bar(_values_list, key, value, title,path):
    """

    :param _values_list:
    :param key:
    :param value:
    :param title:
    :param path:
    :return:
    """
    if len(_values_list) > 0:
        _data = pd.DataFrame(_values_list)
        _data.columns = [key, value]

        _data.plot(title=title, x=key, grid=True, kind='bar')
        plt.tight_layout()
        plt.savefig(path, bbox_inches='tight')
        plt.clf()
        plt.close()
    else:
        print("Empty list in plot_bar.")


def plot_duration(_infected_ips, path, _title="Hours of Activity"):

    mirai_data = pd.read_csv(MIRAI_PATH)
    infected_ips = pd.DataFrame(list(_infected_ips))
    infected_ips.columns = ["infected"]
    mirai_data = mirai_data.drop_duplicates(subset=['ip'])
    mirai_data["fseen"] = pd.to_datetime(mirai_data["fseen"], infer_datetime_format=False)
    mirai_data["lseen"] = pd.to_datetime(mirai_data["lseen"], infer_datetime_format=False)
    mirai_data = mirai_data[mirai_data["ip"].isin(infected_ips["infected"])]  # only infected left
    time_diff = pd.Series(mirai_data['lseen'] - mirai_data['fseen'], name="duration")
    time_diff = time_diff.to_frame()
    time_diff.describe().to_csv(path + "_with_zeros.csv")
    time_diff = time_diff[time_diff["duration"] != pd.Timedelta('0 days 00:00:00')]
    time_diff.describe().to_csv(path + "_no_zeros.csv")

    # START PLOTTING
    (time_diff["duration"] / pd.Timedelta(hours=1)).plot(kind="hist",
                                                     title=_title,
                                                     bins=range(0, 200, 2)
                                                     ).set_xlabel("Active in hours")
    plt.tight_layout()
    plt.savefig(path + ".png", bbox_inches='tight')
    plt.clf()
    plt.close()





def generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    path_to_mirai, _date_limit="2018-12-04T00:00:00Z", _seen="fseen",
                    _filter_port=False, _filter_date=False, outfile_base_name="output"):
    """

    :param censys_ips: set of all censys ips
    :param censys_telnet23: set of ips with port 23/2323
    :param censys_with_banners: set of censys ips with banners
    :param censys_empty_banners: set of censys ips without banners
    :param _banners_map: ip --> banner
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

    print()  # empty line



    mirai_ips = load_mirai_ips_filter_date_port(
        path_to_mirai,
        date_limit=_date_limit,
        seen=_seen,
        filter_port=_filter_port,
        filter_date=_filter_date)
    print("Loaded %d IPs from MIRAI." % len(mirai_ips))

    # intersection
    infected = match_mirai_censys(mirai_ips, censys_ips)
    # stats
    prefix_count, country_count, asn_count = get_counts(infected.copy(), path_to_mirai)
    # Line below limits sets of banners to the infected ones
    banners_count_not_empty, count_empty_banners = infected_banners_stats(infected, censys_empty_banners)

    print("Infected total: ", len(infected))
    print("Infected with banners", banners_count_not_empty)
    print("Infected without banners", count_empty_banners)

    # maps banner to a list of ips (banner --> [ip1, ip2]
    banners2ips = group_by_banners(infected_ips=infected, banner_map=_banners_map)

    ########################## Export infected IPs ###############################################
    outfile = open(outfile_base_name + "_infected.csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')

    out_writer.writerow(["Infected total",len(infected)])
    out_writer.writerow(["Infected with banners", banners_count_not_empty])
    out_writer.writerow(["Infected without banners", count_empty_banners])
    for inf in infected:
        out_writer.writerow([inf])

    ########################## Export Counters ###############################################
    export_banners(outfile_base_name, banners2ips, "banners2ips", version=2)
    export_counters(outfile_base_name, prefix_count, "prefix_count")
    export_counters(outfile_base_name, country_count, "country_count")
    export_counters(outfile_base_name, asn_count, "asn_count")

    # Add plots for below
    temp_list = []
    print("\n################# Prefix top 10 #########################")
    for key, value in prefix_count.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    plot_bar(temp_list, key="Prefix", value="Count",
             title="Number of infected devices grouped by Prefix",
             path = outfile_base_name + "_prefix.png")
    temp_list = []

    print("\n################# Country top 10 #########################")
    for key, value in country_count.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    plot_bar(temp_list, key="Country", value="Count",
             title="Number of infected devices grouped by country",
             path=outfile_base_name + "_country.png")
    temp_list = []

    print("\n################# ASN top 10 #########################")
    for key, value in asn_count.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    plot_bar(temp_list, key="ASN", value="Count",
             title="Number of infected devices grouped by ASN number",
             path=outfile_base_name + "_asn.png")
    temp_list = []

    ### Plot durations for this data
    plot_duration(infected, outfile_base_name + "_duration")

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


if __name__ == '__main__':
    # get all censys info

    censys_ips, censys_with_banners, censys_empty_banners, _banners_map, not23count = \
        load_censys_ips(JSON_DATA_DIR)

    print("Censys IPs (port 23 or 2323): ", len(censys_ips))
    print("Censys IPs (other ports): ", not23count)
    print("Censys with banners: ", len(censys_with_banners))
    print("Censys without banners: ", len(censys_empty_banners))

    # Use all data
    generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    MIRAI_PATH, _date_limit="2018-12-04T00:00:00Z",
                    _seen="fseen", _filter_port=False, _filter_date=False, outfile_base_name="new_results/all/all")

    # Match only data from MIRAI where port 23 or 2323 were used
    generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    MIRAI_PATH, _date_limit="2018-12-04T00:00:00Z",
                    _seen="fseen", _filter_port=True, _filter_date=False,
                    outfile_base_name="new_results/port23_only/port23")

    # Match only data from MIRAI after date [_date_limit]
    generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    MIRAI_PATH, _date_limit="2018-12-04T00:00:00Z",
                    _seen="fseen", _filter_port=False, _filter_date=True,
                    outfile_base_name="new_results/past04_only/past04")

    # Match only data from MIRAI where port 23 or 2323 were used and after date [_date_limit]
    generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    MIRAI_PATH, _date_limit="2018-12-04T00:00:00Z",
                    _seen="fseen", _filter_port=True, _filter_date=True,
                    outfile_base_name="new_results/port23_past04_only/port23_past04")



