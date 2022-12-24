import glob
import json
from matplotlib import pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

COLORS = {
    'Kyber512+Dilithium3': "#B79762",
    'Kyber768+Dilithium3': "#FF4A46",
    'Kyber1024+Dilithium5': "#0000A6"
}

def get_samples(path):
    f = open(path)
    data = json.load(f)
    f.close()
    iters = np.asarray(data["iters"])
    times = np.asarray(data["times"])
    samples = times/iters
    return samples

def load_data(pathfile):
    headers = ["Algorithm", "Clients", "Round", "Time"]
    all_samples = np.array([headers])
    for path in glob.glob(pathfile + "*/*/**"):
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
        row = lambda time: [alg, clients, round, time] 
        rows = np.asarray(list(map(row, samples)))
        all_samples = np.append(all_samples, rows, axis=0)
    return  all_samples

def save_to_csv(input_path, output_path):
    data = load_data(input_path)
    columns = data[0]
    data = np.delete(data, 0, 0)
    df = pd.DataFrame(data, columns = columns)
    df.to_csv(output_path + 'data.csv', index=False)

def load_csv(input_path):
    df = pd.read_csv(input_path + 'data.csv')
    return df


def plot_scalability(input_path, output_path):

    df = load_csv(input_path)
    print(df)
    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.suptitle('Scalability', fontsize=20)
    fig.subplots_adjust(hspace=0.0, wspace=0.0)
    df2 = df[df['Round'] != 'Registration']

    df2 = df2.groupby(['Algorithm', 'Clients', 'Round'])['Time'].mean().reset_index()
    df2 = df2.groupby(['Algorithm', 'Clients'])['Time'].sum().reset_index()
    print(df2)

    p = sns.lineplot(ax=axes, x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS, linewidth=4, style="Algorithm", markers=True, dashes=False)
    axes.set_xlabel('Number of clients', fontsize="x-large")
    axes.set_ylabel('Time (nanoseconds)', fontsize="x-large")

    h, l = p.get_legend_handles_labels()
    l, h = zip(*sorted(zip(l, h)))
    p.legend(h, l)

    figname = "{}scalability_time.png".format(output_path)
    fig.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def plot_scalability2(input_path, output_path):

    df = load_csv(input_path)
    print(df)
    fig, axes = plt.subplots(1, figsize=(18,9), dpi=300, sharey=False)
    fig.suptitle('Round', fontsize=20)
    fig.subplots_adjust(hspace=0.0, wspace=0.0)
    df2 = df[df['Round'] != 'Registration']

    p = sns.barplot(ax=axes, x="Clients", y="Time", hue="Algorithm", data=df2, palette=COLORS)
    axes.set_xlabel('Number of clients', fontsize="x-large")
    axes.set_ylabel('Time (nanoseconds)', fontsize="x-large")

    h, l = p.get_legend_handles_labels()
    l, h = zip(*sorted(zip(l, h)))
    p.legend(h, l)

    figname = "{}round_time.png".format(output_path)
    fig.savefig(figname, bbox_inches="tight")
    print("Saved file to {}".format(figname), flush=True)

def main(): 
    PATH = "./target/criterion/Protocol"
    OUTPUT = "./target/criterion/"
    save_to_csv(PATH, OUTPUT)
    plot_scalability(OUTPUT, OUTPUT)
    plot_scalability2(OUTPUT, OUTPUT)

if __name__ == '__main__':
    main()