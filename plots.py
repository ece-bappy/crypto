import matplotlib.pyplot as plt
import csv
from io import StringIO

csv_data = """Type,File Size Before,File Size After,Encryption Time,Decryption Time,Memory Usage,CPU Usage
3DES,1048576,1048584,0.034915924072266,0.033443450927734,94.35,7.00
AES,1048576,1048592,0.003017663955688,0.002860784530640,96.36,1.30
RSA,1048576,1048592,0.003000974655151,0.008014917373657,94.51,8.94
ECC,1048576,1048592,0.003000974655151,0.005001068115234,96.68,2.50
3DES,104857600,104857608,3.435362577438354,3.332800865173340,393.68,9.03
AES,104857600,104857616,0.259881973266602,0.259276390075684,591.68,8.57
RSA,104857600,104857616,0.250622749328613,0.260753154754639,491.69,9.20
ECC,104857600,104857616,0.260083198547363,0.255101203918457,591.70,10.57
3DES,1073741824,1073741832,40.025921344757080,34.439447879791260,1654.81,9.28
AES,1073741824,1073741840,36.640635967254639,3.065970420837402,214.10,7.90
RSA,1073741824,1073741840,27.456101417541504,3.128250360488892,398.81,8.23
ECC,1073741824,1073741840,23.963418245315552,3.342717885971069,1446.55,12.41
"""

# Read the CSV data
data = StringIO(csv_data)
reader = csv.DictReader(data)
rows = list(reader)

# Prepare data for plotting
encryption_types = set(row['Type'] for row in rows)
file_sizes = sorted(list(set(int(row['File Size Before']) for row in rows)))

encryption_times = {enc_type: [] for enc_type in encryption_types}
decryption_times = {enc_type: [] for enc_type in encryption_types}
memory_usages = {enc_type: [] for enc_type in encryption_types}
cpu_usages = {enc_type: [] for enc_type in encryption_types}

for enc_type in encryption_types:
    for size in file_sizes:
        for row in rows:
            if row['Type'] == enc_type and int(row['File Size Before']) == size:
                encryption_times[enc_type].append(float(row['Encryption Time']))
                decryption_times[enc_type].append(float(row['Decryption Time']))
                memory_usages[enc_type].append(float(row['Memory Usage']))
                cpu_usages[enc_type].append(float(row['CPU Usage']))
                break  # Move to the next file size once a match is found

# Create the plot for Encryption Time
plt.figure(figsize=(10, 6))
for enc_type in encryption_types:
    plt.plot(file_sizes, encryption_times[enc_type], marker='o', linestyle='-', label=enc_type)
plt.xlabel("File Size (Bytes)")
plt.ylabel("Encryption Time (Seconds)")
plt.title("Encryption Time vs File Size")
plt.xscale('log')
plt.yscale('log')
plt.legend()
plt.grid(True)
plt.savefig("encryption_time_vs_file_size.png")
plt.show()

# Create the plot for Decryption Time
plt.figure(figsize=(10, 6))
for enc_type in encryption_types:
    plt.plot(file_sizes, decryption_times[enc_type], marker='o', linestyle='-', label=enc_type)
plt.xlabel("File Size (Bytes)")
plt.ylabel("Decryption Time (Seconds)")
plt.title("Decryption Time vs File Size")
plt.xscale('log')
plt.yscale('log')
plt.legend()
plt.grid(True)
plt.savefig("decryption_time_vs_file_size.png")
plt.show()

# Create the plot for Memory Usage
plt.figure(figsize=(10, 6))
for enc_type in encryption_types:
    plt.plot(file_sizes, memory_usages[enc_type], marker='o', linestyle='-', label=enc_type)
plt.xlabel("File Size (Bytes)")
plt.ylabel("Memory Usage (MB)")
plt.title("Memory Usage vs File Size")
plt.xscale('log')
plt.yscale('linear')
plt.legend()
plt.grid(True)
plt.savefig("memory_usage_vs_file_size.png")
plt.show()

# Create the plot for CPU Usage
plt.figure(figsize=(10, 6))
for enc_type in encryption_types:
    plt.plot(file_sizes, cpu_usages[enc_type], marker='o', linestyle='-', label=enc_type)
plt.xlabel("File Size (Bytes)")
plt.ylabel("CPU Usage (%)")
plt.title("CPU Usage vs File Size")
plt.xscale('log')
plt.yscale('linear')
plt.legend()
plt.grid(True)
plt.savefig("cpu_usage_vs_file_size.png")
plt.show()