import csv
import json
import os
from collections import Counter
import pandas as pd
import loaders as loaders
import config as config
import plot_methods as my_plt


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
        if filter_by_port and int(row[config.DST_PORT]) != 23 and int(row[config.DST_PORT]) != 2323:
            continue  # skip this row, we don't care about this port
        if len(row[0]) > 2:
            if row[0] in infected_ips:
                prefix_count[row[config.PREFIX]] += 1
                country_count[row[config.COUNTRY]] += 1
                asn_count[row[config.ASN]] += 1
                # remove from the set to not count twice
                infected_ips.remove(row[0])
    print("Counting prefixes, countries and asn numbers done. ")

    return prefix_count, country_count, asn_count


def group_by(path_to_mirai, outfile, _censys_ips, by=config.ASN):
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
        if not isinstance(row[config.IP], str):
            raise ValueError('Not a string: %s' % row[0])
        if " " in row[0]:
            raise ValueError("IP contains Whitespace %s" % row[0])

        if row[config.IP] in _censys_ips:
            if row[config.IP] in mappings:
                mappings[row[config.IP]].add(row[by])
            else:
                mappings[row[config.IP]] = set()
                mappings[row[config.IP]].add(row[by])

    outfile = open(outfile, "w")
    out_writer = csv.writer(outfile, dialect='excel')
    for key, value in sorted(mappings.items(), key=lambda e: -(len(e[1]))):
        out_writer.writerow([key] + list(value))


def count_ports(infected_ips, path_to_mirai):
    """
    Gets stats in form of port_number => total of unique infected ips
    Notice, it modifies the parameter infected_ips, thus a copy should be passed
    if you need the original object to preserve its state for later.

    :param infected_ips: list of infected ips from censys
    :param path_to_mirai:
    :return: dict()
    """
    port_count = Counter()
    mirai_file = open(path_to_mirai, "r")
    mirai_reader = csv.reader(mirai_file, dialect='excel')

    for row in mirai_reader:
        if len(row[config.IP]) > 2:
            if row[config.IP] in infected_ips:
                if row[config.DST_PORT] in port_count.keys():
                    port_count[row[config.DST_PORT]] += 1
                else:
                    port_count[row[config.DST_PORT]] = 1
                # remove from the set to not count twice
    print("Counting done. ")
    return port_count


def group_by_banners(infected_ips, banner_map):
    """

    :param infected_ips:
    :param banner_map
    :return: a dictionary in form of dict[banner] = [list of ips with that banner]
    """
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


def count_devices(dir_path_censys, infected_ips):
    ASN_TOP10 = [12389, 4837, 4134, 8452, 3462, 4766, 18403, 8376, 24444, 9121]
    # to find devices for given most common asns
    asn_device_map = dict()
    for a in ASN_TOP10:
        asn_device_map[a] = Counter()
    # get censys files
    files = os.listdir(dir_path_censys)  # list all files from the directory
    # some sets and counters
    devices_counter = Counter()  # count devices
    found = set()  # helper to keep devices unique
    multi_device_ips = set()  # get ips with multiple devices
    multi_device_asn = set()  # get asns with multiple devices
    multi_country_counter = Counter()  # count countries with multiple devices
    no_description = 0
    for _file in files:
        data = loaders.load_scan(dir_path_censys + "/" + _file)
        for d in data:
            d = json.loads(d)
            if d['ip'] in infected_ips:  # check if this ip was infected
                try:
                    if ',' in d['description']:
                        devices = d['description'].split(',')
                        if devices[0] == devices[1]:  # repetitions mikrotik, mikrotik ...
                            if d['ip'] + devices[0] not in found:  # don't count repetitions
                                devices_counter[devices[0]] += 1
                                found.add(d['ip'] + devices[0])
                                if int(d['asn']) in ASN_TOP10:
                                    asn_device_map[int(d['asn'])][devices[0]] += 1
                        else:
                            for dev in devices:
                                if d['ip'] + dev not in found:  # don't count repetitions
                                    devices_counter[dev] += 1
                                    found.add(d['ip'] + dev)
                                    if int(d['asn']) in ASN_TOP10:
                                        asn_device_map[int(d['asn'])][dev] += 1
                                    multi_device_ips.add(d['ip'])
                                    multi_device_asn.add(d['asn'])
                                    multi_country_counter[d['country_code']] += 1
                    elif ' ' in d['description']:
                        split_ = d['description'].split(' ')
                        if len(split_) == 2:
                            if d['ip'] + d['description'] not in found:  # don't count repetitions
                                devices_counter[d['description']] += 1
                                found.add(d['ip'] + d['description'])
                                if int(d['asn']) in ASN_TOP10:
                                    asn_device_map[int(d['asn'])][d['description']] += 1
                        else:  # length longer than 3, expect repetition
                            if d['ip'] + split_[0] not in found:  # don't count repetitions
                                devices_counter[split_[0]] += 1
                                found.add(d['ip'] + split_[0])
                                if int(d['asn']) in ASN_TOP10:
                                    asn_device_map[int(d['asn'])][split_[0]] += 1
                except KeyError as ke:  # that entry does not have description field
                    no_description += 1
                    continue
    print("No description column: ", no_description)
    print("Number of IPs attacked on multiple devices: ", len(multi_device_ips))
    pd.DataFrame(list(multi_device_ips)).to_csv("multi_device_ips.csv")
    pd.DataFrame(list(multi_device_asn)).to_csv("multi_device_asn.csv")

    temp_list = []
    i = 0
    for key, value in devices_counter.most_common():
        print(key, "\t", value)
        if i < 10:  # add only 10 most common for plotting
            temp_list.append((key, value))

    my_plt.plot_bar(temp_list, key="Device", value="Count",
                    title="Top 10 most often attacked devices",
                    path="devices.png")

    temp_list = []
    for key, value in multi_country_counter.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    my_plt.plot_bar(temp_list, key="Country Code", value="Count",
                    title="Countries where one IP was attacked on multiple devices",
                    path="multi_country.png")

    for key, value in asn_device_map.items():
        print("Most common devices with asn number %d" % key)
        for k, v in value.most_common():
            print(k, '\t', v)


def load_data_and_count_devices(_censys_ips, dir_path_censys, path_to_mirai, _date_limit, _seen, _filter_port,
                                _filter_date):
    mirai_ips = loaders.load_mirai_ips_filter_date_port(
        path_to_mirai,
        date_limit=_date_limit,
        seen=_seen,
        filter_port=_filter_port,
        filter_date=_filter_date)
    print("Loaded %d IPs from MIRAI." % len(mirai_ips))

    # intersection
    infected = match_mirai_censys(mirai_ips, _censys_ips)
    print("found %d infected devices" % len(infected))
    print("Getting device statistics... ")
    count_devices(dir_path_censys, infected)


def generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    path_to_mirai, _date_limit="2018-12-04T00:00:00Z", _seen="fseen",
                    _filter_port=False, _filter_date=False, outfile_base_name="output"):
    """

    :param censys_ips: set of all censys ips
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

    mirai_ips = loaders.load_mirai_ips_filter_date_port(
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
    port_counts = count_ports(infected_ips=infected.copy(), path_to_mirai=path_to_mirai)

    group_by(path_to_mirai=path_to_mirai,
             outfile=outfile_base_name + "ips2asn",
             _censys_ips=infected,
             by=config.ASN)
    group_by(path_to_mirai=path_to_mirai,
             outfile=outfile_base_name + "_ips2country",
             _censys_ips=infected,
             by=config.COUNTRY)

    ########################## Export infected IPs ###############################################
    outfile = open(outfile_base_name + "_infected.csv", "w")
    out_writer = csv.writer(outfile, dialect='excel')

    out_writer.writerow(["Infected total", len(infected)])
    out_writer.writerow(["Infected with banners", banners_count_not_empty])
    out_writer.writerow(["Infected without banners", count_empty_banners])
    for inf in infected:
        out_writer.writerow([inf])

    ########################## Export Counters ###############################################
    loaders.export_banners(outfile_base_name, banners2ips, "banners2ips", version=2)
    loaders.export_counters(outfile_base_name, prefix_count, "prefix_count")
    loaders.export_counters(outfile_base_name, country_count, "country_count")
    loaders.export_counters(outfile_base_name, port_counts, "ports_count")

    # Add plots for below
    temp_list = []
    print("\n################# Prefix top 10 #########################")
    for key, value in prefix_count.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    my_plt.plot_bar(temp_list, key="Prefix", value="Count",
                    title="Number of infected devices grouped by Prefix",
                    path=outfile_base_name + "_prefix.png")
    temp_list = []

    print("\n################# Country top 10 #########################")
    for key, value in country_count.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    my_plt.plot_bar(temp_list, key="Country", value="Count",
                    title="Number of infected devices grouped by country",
                    path=outfile_base_name + "_country.png")
    temp_list = []

    print("\n################# ASN top 10 #########################")
    for key, value in asn_count.most_common(10):
        print(key, "\t", value)
        temp_list.append((key, value))

    my_plt.plot_bar(temp_list, key="ASN", value="Count",
                    title="Number of infected devices grouped by ASN number",
                    path=outfile_base_name + "_asn.png")
    temp_list = []

    ### Plot durations for this data
    my_plt.plot_duration(infected, outfile_base_name + "_duration")


if __name__ == '__main__':
    # get all censys info

    censys_ips, censys_with_banners, censys_empty_banners, _banners_map, not23count = \
        loaders.load_censys_ips(config.JSON_DATA_DIR)

    print("Censys IPs (port 23 or 2323): ", len(censys_ips))
    print("Censys IPs (other ports): ", not23count)
    print("Censys with banners: ", len(censys_with_banners))
    print("Censys without banners: ", len(censys_empty_banners))

    # Match only data from MIRAI where port 23 or 2323 were used and after date [_date_limit]
    
    generate_report(censys_ips, censys_with_banners, censys_empty_banners, _banners_map,
                    config.MIRAI_PATH, _date_limit="2018-12-04T00:00:00Z",
                    _seen="fseen", _filter_port=True, _filter_date=True,
                    outfile_base_name="../new_results/port23_past04_only/port23_past04")
    
    load_data_and_count_devices(censys_ips, config.JSON_DATA_DIR, config.MIRAI_PATH,
                                _date_limit="2018-12-04T00:00:00Z",
                                _seen="fseen", _filter_port=True, _filter_date=True)

    """
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

    """
