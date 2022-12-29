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
    CLASSIC_PKE_SIG: "#FF34FF",
    CLASSIC_PKE: "#FF8A9A",
    CLASSIC_SIG: "#FFF69F",
    'Kyber512': "#3B5DFF",
    'Kyber768': "#4FC601",
    'Kyber1024': "#FAD09F",
    'Dilithium2': "#006FA6",
    'Dilithium3': "#A30059",
    'Dilithium5': "#008941",
}

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
        else:
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
    return  all_samples

def load_data_protocol(pathfile):
    headers = ["Algorithm", "Clients", "Round", "Time", "Kind"]
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
            row = lambda time: [alg, clients, round, time, kind] 
            rows = np.asarray(list(map(row, samples)))
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
            row = lambda time: [alg, clients, round, time, kind] 
            rows = np.asarray(list(map(row, samples)))
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

def plot_scalability(df, output_path):
    # print(df)
    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0.0, wspace=0.0)
    df2 = df[df['Round'] != 'Registration']

    df2 = df2.groupby(['Algorithm', 'Clients', 'Round'])['Time'].mean().reset_index()
    df2 = df2.groupby(['Algorithm', 'Clients'])['Time'].sum().reset_index()
    df2['Time'] = df2['Time'] / 1000000
    
    p = sns.lineplot(ax=axes, x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, linewidth=4, style="Algorithm", markers=True, dashes=False)
    axes.set_xlabel('Number of clients', fontsize="x-large")
    axes.set_ylabel('Time (milliseconds)', fontsize="x-large")

    h, l = p.get_legend_handles_labels()
    l, h = zip(*sorted(zip(l, h)))
    p.legend(h, l)
    reorderLegend(p, ["Kyber512+Dilithium2", "Kyber768+Dilithium3", "Kyber1024+Dilithium5"])

    figname = "{}scalability.png".format(output_path)
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
        p = sns.barplot(ax=axes[row, col], x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=["Kyber512+Dilithium2", "Kyber768+Dilithium3", "Kyber1024+Dilithium5", CLASSIC_PKE_SIG])

        axes[row, col].set_xlabel('Number of clients', fontsize="x-large")
        axes[row, col].set_ylabel('Time (milliseconds)', fontsize="x-large")
        axes[row, col].set_title(round, fontsize="x-large")
        axes[row, col].get_legend().remove()

    h, l = p.get_legend_handles_labels()
    l, h = zip(*sorted(zip(l, h)))
    p.legend(h, l)

    reorderLegend(axes[0, 2], ["Kyber512+Dilithium2", "Kyber768+Dilithium3", "Kyber1024+Dilithium5", CLASSIC_PKE_SIG])
    # axes[0, 2].legend(h, l, bbox_to_anchor=(1.05, 1.05))
    axes[1, 2].get_legend().remove()
    figname = "{}rounds.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_registration(df, output_path):

    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0, wspace=0)
    df2 = df[df['Round'] == 'Registration']
    df2['Time'] = df2['Time'] / 1000000
    # print("------------")
    # print(df2)

    p = sns.barplot(ax=axes, x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=["Kyber512+Dilithium2", "Kyber768+Dilithium3", "Kyber1024+Dilithium5", CLASSIC_PKE_SIG])
    axes.set_xlabel('Number of clients', fontsize="x-large")
    axes.set_ylabel('Time (milliseconds)', fontsize="x-large")

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

    p = sns.barplot(ax=axes, x="Operation", y="Time", hue="Algorithm", data=df2, palette=COLORS, hue_order=["Kyber512", "Kyber768", "Kyber1024", CLASSIC_PKE], order=["KEYGEN", "ENC", "DEC"])
    axes.set_xlabel('Operation', fontsize="x-large")
    axes.set_ylabel('Time (microseconds)', fontsize="x-large")

    figname = "{}pke.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_sig(df, output_path):

    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.subplots_adjust(hspace=0, wspace=0)

    df2 = df[df['Type'] == 'SIG']
    df2['Time'] = df2['Time'] / 1000

    p = sns.barplot(ax=axes, x="Operation", y="Time", hue="Algorithm", data=df2, palette=COLORS, order=["KEYGEN", "SIG", "VRY"], hue_order=["Dilithium2", "Dilithium3", "Dilithium5", CLASSIC_SIG])
    axes.set_xlabel('Operation', fontsize="x-large")
    axes.set_ylabel('Time (microseconds)', fontsize="x-large")

    figname = "{}sig.png".format(output_path)
    plt.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)


def main(): 
    PATH = "./target/criterion/Protocol"
    OUTPUT = "./target/criterion/"
    save_to_csv_protocol(PATH, OUTPUT, 'data.csv')
    df_protocol = load_csv(OUTPUT, 'data.csv')
    plot_scalability(df_protocol, OUTPUT)
    plot_rounds(df_protocol, OUTPUT)
    plot_registration(df_protocol, OUTPUT)
    
    save_to_csv_primitives([OUTPUT + "PKE", OUTPUT + "SIG"], OUTPUT, "data_primitives.csv")
    df_primitives = load_csv(OUTPUT, 'data_primitives.csv')
    plot_pke(df_primitives, OUTPUT)
    plot_sig(df_primitives, OUTPUT)

if __name__ == '__main__':
    main()