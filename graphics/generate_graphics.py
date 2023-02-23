import glob
import itertools
import json
from matplotlib import pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

CLASSIC_SIG = "ECDSA(seckp256k1)"
CLASSIC_PKE = "ECIES(seckp256k1)"
CLASSIC_PKE_SIG = "ECIES+ECDSA(seckp256k1)"

COLORS = {
    'Kyber512+Dilithium2': "#B79762",
    'Kyber768+Dilithium3': "#FF4A46",
    'Kyber1024+Dilithium5': "#0000A6",
    'ClassicMcEliece6960119f+Dilithium5': '#FDE74C',
    'ClassicMcEliece460896f+Dilithium3': '#F49C28',
    'ClassicMcEliece348864f+Dilithium2': '#00FF00',
    CLASSIC_PKE_SIG: "#FF34FF",
    CLASSIC_PKE: "#FF34FF",
    CLASSIC_SIG: "#FFF69F",
    'Kyber512': "#B79762",
    'Kyber768': "#FF4A46",
    'Kyber1024': "#0000A6",
    'Dilithium2': "#006FA6",
    'Dilithium3': "#A30059",
    'Dilithium5': "#008941",
    'ClassicMcEliece6960119f': '#FDE74C',
    'ClassicMcEliece460896f': '#F49C28',
    'ClassicMcEliece348864f': '#00FF00',
}

SPEEDS = {
    '2G': 5000, # 5 kB/s
    '3G': 1000000, # 1 MB/s
    '4G': 6000000, # 6 MB/s
    '5G': 125000000 # 125 MB/s
}

HUE_ORDER = ["Kyber512+Dilithium2", "Kyber768+Dilithium3", "Kyber1024+Dilithium5", 'ClassicMcEliece348864f+Dilithium2', 'ClassicMcEliece460896f+Dilithium3', 'ClassicMcEliece6960119f+Dilithium5', CLASSIC_PKE_SIG]

FONTSIZE = 20
LABELSIZE = 15
LEGENDSIZE = 15

rc = {'lines.linewidth': 2}                  
sns.set_context("paper", rc = rc) 

def get_length_data(path):
    headers = ["Kind", "Algorithm", "Clients", "Bandwidth"]
    files = glob.glob(path + "*-*.csv")
    data = np.array([headers])
    for file in files:
        file_s = file.split("-")
        kind = file_s[0].split("/")[-1].upper()
        pke = file_s[1]
        sig = file_s[2]
        if kind == "PQ":
            alg = pke + "+" + sig
        else:
            alg = CLASSIC_PKE_SIG
        clients = int(file_s[3].replace(".csv", ""))
        df = pd.read_csv(file, header=None)
        d = [kind, alg, clients, int(np.sum(df, axis = 1))]
        data = np.vstack([data, d])
    return data

def save_to_csv_bandwidth(input_path, output_path, filename):
    data = get_length_data(input_path)
    columns = data[0]
    data = np.delete(data, 0, 0)
    df = pd.DataFrame(data, columns = columns)
    df.to_csv(output_path + filename, index=False)

def get_samples(path):
    f = open(path)
    data = json.load(f)
    f.close()
    iters = np.asarray(data["iters"])
    times = np.asarray(data["times"])
    samples = times/iters
    return samples

def load_data_primitives(pathfiles):
    headers = ["Algorithm", "Type", "Operation", "Time", "Kind"]
    all_samples = np.array([headers])
    paths = list(itertools.chain(*list(map(lambda x: glob.glob(x + "*/*/*"), pathfiles))))
    paths = list(filter(lambda x: "PQ" in x or x.endswith("base"), paths))
    for path in paths:
        type_kind = path.split("/")[-3]
        type_ = type_kind.split("_")[0]
        kind = type_kind.split("_")[1]
        if(kind == "PQ"):
            alg = path.split("/")[-1]
            operation = path.split("/")[-2]
            data_path_base = "{}/{}/sample.json".format(path, "base")
            data_path_new = "{}/{}/sample.json".format(path, "new")
            samples_base = get_samples(data_path_base)
            samples_new = get_samples(data_path_new)
            samples = np.concatenate((samples_base, samples_new))
            row = lambda time: [alg, type_, operation, time, kind] 
            rows = np.asarray(list(map(row, samples)))
            all_samples = np.append(all_samples, rows, axis=0)
        elif (kind == "CLASSIC"):
            operation = path.split("/")[-2]
            if type_ == "PKE":
                alg = CLASSIC_PKE
            elif type_ == "SIG":
                alg = CLASSIC_SIG
            else:
                raise Exception("Error reading file!")
            data_path_base = "{}/sample.json".format(path, "base")
            data_path_new = "{}/sample.json".format(path, "new")
            samples_base = get_samples(data_path_base)
            samples_new = get_samples(data_path_new)
            samples = np.concatenate((samples_base, samples_new))
            row = lambda time: [alg, type_, operation, time, kind] 
            rows = np.asarray(list(map(row, samples)))
            all_samples = np.append(all_samples, rows, axis=0)
        else:
            raise Exception("Error while reading file!")
    return  all_samples

def load_data_protocol(pathfile):
    headers = ["Id", "Algorithm", "Clients", "Round", "Time", "Kind"]
    all_samples = np.array([headers])
    for path in glob.glob(pathfile + "*/*/**"):
        check = len(path.split("/")[-1].split("-"))
        if (check > 1):
            kind = "PQ"
            alg_clients = path.split("/")[-1]
            alg = alg_clients.split("-")[0] + "+" + alg_clients.split("-")[1]
            clients = alg_clients.split("-")[-1]
            round = path.split("/")[-2]
            # print(alg_clients)
            # print(round)
            data_path_base = "{}/{}/sample.json".format(path, "base")
            data_path_new = "{}/{}/sample.json".format(path, "new")
            samples_base = get_samples(data_path_base)
            samples_new = get_samples(data_path_new)
            samples = np.concatenate((samples_base, samples_new))
            # print(samples)
            row = lambda x: [x[0], alg, clients, round, x[1], kind] 
            rows = np.asarray(list(map(row, enumerate(samples))))
            all_samples = np.append(all_samples, rows, axis=0)
        else:
            kind = "CLASSIC"
            clients = path.split("/")[-1]
            round = path.split("/")[-2]
            # print(path)
            data_path_base = "{}/{}/sample.json".format(path, "base")
            data_path_new = "{}/{}/sample.json".format(path, "new")
            samples_base = get_samples(data_path_base)
            samples_new = get_samples(data_path_new)
            samples = np.concatenate((samples_base, samples_new))
            # print(samples)
            alg = CLASSIC_PKE_SIG
            row = lambda x: [x[0], alg, clients, round, x[1], kind] 
            rows = np.asarray(list(map(row, enumerate(samples))))
            all_samples = np.append(all_samples, rows, axis=0)

    return  all_samples

def save_to_csv_protocol(input_path, output_path, filename):
    data = load_data_protocol(input_path)
    columns = data[0]
    data = np.delete(data, 0, 0)
    df = pd.DataFrame(data, columns = columns)
    df.to_csv(output_path + filename, index=False)

def save_to_csv_primitives(inputs_path, output_path, filename):
    data = load_data_primitives(inputs_path)
    columns = data[0]
    data = np.delete(data, 0, 0)
    df = pd.DataFrame(data, columns = columns)
    df.to_csv(output_path + filename, index=False)

def load_csv(input_path, filename):
    df = pd.read_csv(input_path + filename)
    return df

#  Returns tuple of handles, labels for axis ax, after reordering them to conform to the label order `order`, and if unique is True, after removing entries with duplicate labels.
def reorderLegend(ax=None,order=None,unique=False):
    if ax is None: ax=plt.gca()
    handles, labels = ax.get_legend_handles_labels()
    labels, handles = zip(*sorted(zip(labels, handles), key=lambda t: t[0])) # sort both labels and handles by labels
    if order is not None: # Sort according to a given list (not necessarily complete)
        keys=dict(zip(order,range(len(order))))
        labels, handles = zip(*sorted(zip(labels, handles), key=lambda t,keys=keys: keys.get(t[0],np.inf)))
    if unique:  labels, handles= zip(*unique_everseen(zip(labels,handles), key = labels)) # Keep only the first of each handle
    ax.legend(handles, labels)
          
    return(handles, labels)

def unique_everseen(seq, key=None):
    seen = set()
    seen_add = seen.add
    return [x for x,k in zip(seq,key) if not (k in seen or seen_add(k))]


def plot_speed(df_bandwidth, output_path, speeds):
    rows = int(len(speeds.keys())/2)
    fig, axes = plt.subplots(rows, rows, figsize=(18,9), dpi=300)

    df2 = df_bandwidth[['Algorithm', 'Clients', 'Bandwidth']]

    for i, key in enumerate(speeds.keys()):
        row = i // rows
        col = i % rows
        df3 = df2[['Algorithm', 'Clients', 'Bandwidth']]
        df3.insert(2, "Bandwidth", 0, True)
        df3.insert(3, "Connection", "", True)
        df3["Speed"] = df2["Bandwidth"]/speeds[key]
        df3["Connection"] = key

        sns.barplot(ax=axes[row, col], x="Clients", y="Speed", hue="Algorithm", data=df3, palette=COLORS, hue_order=HUE_ORDER, errorbar="sd")

        axes[row, col].set_title(key, fontsize=FONTSIZE)
        axes[row, col].set_xlabel('Number of clients', fontsize=FONTSIZE)
        axes[row, col].set_ylabel('Time (seconds)', fontsize=FONTSIZE)
        axes[row, col].set_yscale('log')
        axes[row, col].tick_params(labelsize=LABELSIZE)
        axes[row, col].tick_params(axis='both', labelsize=LABELSIZE)
        

        if row != 0 or col != 0:
            axes[row, col].get_legend().remove()

    h, l = reorderLegend(axes[0,0], HUE_ORDER)
    fig.legend(h, l, loc='upper center', bbox_to_anchor=(0.5, 0.05),
          fancybox=True, ncol=3, fontsize=LEGENDSIZE)

    axes[0,0].get_legend().remove()    
    
    fig.subplots_adjust(hspace=0.35)

    figname = "{}speed.png".format(output_path)
    fig.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_scalability_time(df, output_path):
    # print(df)
    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300)
    
    df2 = df[df['Round'] != 'Registration']

    # df2 = df2.groupby(['Algorithm', 'Clients', 'Round'])['Time'].mean().reset_index()
    print(df2)
    df2 = df2.groupby(['Id', 'Algorithm', 'Clients'])['Time'].sum().reset_index()
    df2['Time'] = df2['Time'] / 1000000

    rc = {'lines.linewidth': 2}                  
    sns.set_context("paper", rc = rc) 

    sns.barplot(ax=axes, x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=HUE_ORDER, errorbar="sd")

    axes.set_xlabel('Number of clients', fontsize=FONTSIZE)
    axes.set_ylabel('Time (milliseconds)', fontsize=FONTSIZE)
    axes.set_yscale('log')
    axes.tick_params(axis='both', labelsize=LABELSIZE)

    fig.subplots_adjust(hspace=0)

    # h, l = ax1.get_legend_handles_labels()
    # l, h = zip(*sorted(zip(l, h)))
    # ax1.legend(h, l)

    # Put a legend below current axis
    h, l = reorderLegend(axes, HUE_ORDER)
    fig.legend(h, l, loc='upper center', bbox_to_anchor=(0.5, 0.03),
          fancybox=True, ncol=3, fontsize=LEGENDSIZE)
    axes.get_legend().remove()

    figname = "{}scalability_time.png".format(output_path)
    fig.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_scalability_bandwidth(df_bandwidth, output_path):
    # print(df)
    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300)

    df_bandwidth['Bandwidth'] = df_bandwidth['Bandwidth'] / 1000000

    rc = {'lines.linewidth': 2}                  
    sns.set_context("paper", rc = rc) 

    sns.barplot(ax=axes, x="Clients", y="Bandwidth", hue="Algorithm", data=df_bandwidth, palette=COLORS, hue_order=HUE_ORDER, errorbar="sd")

    axes.set_xlabel('Number of clients', fontsize=FONTSIZE)
    axes.set_yscale('log')
    axes.set_ylabel('Bandwidth (MB)', fontsize=FONTSIZE)
    axes.tick_params(axis='both', labelsize=LABELSIZE)

    fig.subplots_adjust(hspace=0)

    # h, l = ax1.get_legend_handles_labels()
    # l, h = zip(*sorted(zip(l, h)))
    # ax1.legend(h, l)

    # Put a legend below current axis
    h, l = reorderLegend(axes, HUE_ORDER)
    fig.legend(h, l, loc='upper center', bbox_to_anchor=(0.5, 0.03),
          fancybox=True, ncol=3, fontsize=LEGENDSIZE)
    axes.get_legend().remove()

    figname = "{}scalability_bandwidth.png".format(output_path)
    fig.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)


def plot_rounds(df, output_path):
    fig, axes = plt.subplots(2, 3, figsize=(30,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0.4, wspace=0.2)
    df2 = df[df['Round'] != 'Registration']

    rounds = ["Round 1", "Round 2", "Round 3", "Round 4", "Round 5", "Round 6"]
    for (i, round) in enumerate(rounds):
        df2 = df[df['Round'] == round]
        df2['Time'] = df2['Time'] / 1000000

        # print(df2)

        row = i // 3
        col = i % 3
        p = sns.barplot(ax=axes[row, col], x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=HUE_ORDER, errorbar="sd")

        axes[row, col].set_xlabel('Number of clients', fontsize=FONTSIZE)
        axes[row, col].set_ylabel('Time (milliseconds)', fontsize=FONTSIZE)
        axes[row, col].set_title(round, fontsize=FONTSIZE)
        axes[row, col].get_legend().remove()
        axes[row, col].set_yscale('log')
        axes[row, col].tick_params(axis='x', labelsize=LABELSIZE)

    h, l = reorderLegend(axes[1,1], HUE_ORDER)
    fig.legend(h, l, loc='upper center', bbox_to_anchor=(0.5, 0.03),
          fancybox=True, ncol=3, fontsize=LEGENDSIZE)


    # axes[0, 2].legend(h, l, bbox_to_anchor=(1.05, 1.05))
    axes[1, 1].get_legend().remove()
    figname = "{}rounds.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_rounds_fixed_clients(df, output_path, clients):
    fig, axes = plt.subplots(len(clients), figsize=(30,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0.4, wspace=0.2)
    df2 = df[df['Round'] != 'Registration']

    order = ["Round 1", "Round 2", "Round 3", "Round 4", "Round 5", "Round 6"]

    for (i, clients_number) in enumerate(clients):
        df2 = df[df['Clients'] == clients_number]
        df2['Time'] = df2['Time'] / 1000000

        p = sns.barplot(ax = axes[i], x="Round", y="Time", hue="Algorithm", data=df2, order=order, palette=COLORS, hue_order=HUE_ORDER, errorbar="sd")

        axes[i].set_xlabel('Round', fontsize=FONTSIZE)
        axes[i].set_ylabel('Time (milliseconds)', fontsize=FONTSIZE)
        axes[i].set_title('{} clients'.format(clients_number), fontsize=FONTSIZE)
        axes[i].get_legend().remove()
        axes[i].set_yscale('log')
        axes[i].tick_params(axis='x', labelsize=LABELSIZE)


    h, l = reorderLegend(axes[i], HUE_ORDER)
    fig.legend(h, l, loc='upper center', bbox_to_anchor=(0.5, 0.03),
          fancybox=True, ncol=3, fontsize=LEGENDSIZE)

    axes[i].get_legend().remove()
    figname = "{}rounds_fixed_clients.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_registration(df, output_path):

    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0, wspace=0)
    df2 = df[df['Round'] == 'Registration']
    df2['Time'] = df2['Time'] / 1000000
    # print("------------")
    # print(df2)

    p = sns.barplot(ax=axes, x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=HUE_ORDER, errorbar="sd")
    axes.set_xlabel('Number of clients', fontsize=FONTSIZE)
    axes.set_ylabel('Time (milliseconds)', fontsize=FONTSIZE)
    axes.set_yscale('log')

    h, l = p.get_legend_handles_labels()
    l, h = zip(*sorted(zip(l, h)))
    p.legend(h, l)

    figname = "{}registration.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)


def plot_pke(df, output_path):

    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0, wspace=0)

    df2 = df[df['Type'] == 'PKE']
    df2['Time'] = df2['Time'] / 1000

    p = sns.barplot(ax=axes, x="Operation", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=["Kyber512", "Kyber768", "Kyber1024", 'ClassicMcEliece348864f', 'ClassicMcEliece460896f', 'ClassicMcEliece6960119f', CLASSIC_PKE], order=["KEYGEN", "ENC", "DEC"], errorbar="sd")
    axes.set_xlabel('Operation', fontsize=FONTSIZE)
    axes.set_ylabel('Time (microseconds)', fontsize=FONTSIZE)
    axes.set_yscale('log')
    axes.tick_params(axis='both', labelsize=LABELSIZE)
    axes.legend(fontsize=LEGENDSIZE)

    figname = "{}pke.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_sig(df, output_path):

    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0, wspace=0)

    df2 = df[df['Type'] == 'SIG']
    df2['Time'] = df2['Time'] / 1000

    p = sns.barplot(ax=axes, x="Operation", y="Time", hue="Algorithm", data=df2, palette=COLORS, order=["KEYGEN", "SIG", "VRY"], hue_order=["Dilithium2", "Dilithium3", "Dilithium5", CLASSIC_SIG], errorbar="sd")
    axes.set_xlabel('Operation', fontsize=FONTSIZE)
    axes.set_ylabel('Time (microseconds)', fontsize=FONTSIZE)
    axes.set_yscale('log')
    axes.tick_params(axis='both', labelsize=LABELSIZE)


    figname = "{}sig.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)


def get_statistics_primitives(df, output):
    # print(df)
    df2 = df[["Algorithm", "Type", "Operation", "Time"]]
    result = df2.groupby(["Algorithm", "Type", "Operation"], as_index=False).agg(
                      {'Time':['mean', 'std', 'count']})

    result.round(3).to_csv(output, index=False)
    result = pd.read_csv(output, names=["Algorithm", "Type", "Operation","Time_mean","Time_std","Samples"], skiprows=2)
    result.round(3).to_csv(output, index=False)

def get_statistics_protocol(df, output):
    # print(df)
    df2 = df[["Algorithm", "Clients", "Round", "Time"]]
    # print(df2)
    result = df2.groupby(["Algorithm", "Clients", "Round"], as_index=False).agg(
                      {'Time':['mean', 'std', 'count']})

    # print(result)
    result.round(3).to_csv(output, index=False)
    result = pd.read_csv(output, names=["Algorithm", "Clients", "Round","Time_mean","Time_std","Samples"], skiprows=2)
    result.round(3).to_csv(output, index=False)

def main(): 
    PATH = "./target/criterion/Protocol"
    OUTPUT = "./target/criterion/"
    CLIENTS = [
        #512,
        1024, 
        16384
    ]

    save_to_csv_protocol(PATH, OUTPUT, 'data.csv')
    df_protocol = load_csv(OUTPUT, 'data.csv')

    save_to_csv_bandwidth(OUTPUT, OUTPUT, 'data_bandwidth.csv')
    df_bandwidth = load_csv(OUTPUT, 'data_bandwidth.csv')

    plot_scalability_time(df_protocol, OUTPUT)
    plot_scalability_bandwidth(df_bandwidth, OUTPUT)
    plot_speed(df_bandwidth, OUTPUT, SPEEDS)
    plot_rounds(df_protocol, OUTPUT)
    plot_rounds_fixed_clients(df_protocol, OUTPUT, CLIENTS)
    #plot_registration(df_protocol, OUTPUT)
    
    save_to_csv_primitives([OUTPUT + "PKE", OUTPUT + "SIG"], OUTPUT, "data_primitives.csv")
    df_primitives = load_csv(OUTPUT, 'data_primitives.csv')
    plot_pke(df_primitives, OUTPUT)
    plot_sig(df_primitives, OUTPUT)

    get_statistics_primitives(df_primitives, OUTPUT + "statistics_primitives.csv")
    get_statistics_protocol(df_protocol, OUTPUT + "statistics_protocol.csv")

if __name__ == '__main__':
    main()