import config as config
import pandas as pd
import matplotlib.pyplot as plt


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

    mirai_data = pd.read_csv(config.MIRAI_PATH)
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


