#!/usr/bin/env python
# coding: utf-8

# In[85]:


import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


# In[86]:


# Load your dataset (assuming it's in a CSV file)
data = pd.read_csv('C:/Users/shaik/Downloads/USNW (1).csv')
data


# In[87]:


# Define the labels from your original list
attack_labels = ["Normal","Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms"]

# Calculate the counts of each attack category
attack_counts = data['attack_cat'].value_counts()

# Sort the labels and values based on the counts in descending order
sorted_attack_labels = sorted(attack_labels, key=lambda label: attack_counts.get(label, 0), reverse=True)

# Choose a color palette from seaborn
color_palette = sns.color_palette("gnuplot2")

# Create the countplot with data labels using the chosen color palette
plt.figure(figsize=(12, 6))
ax = sns.countplot(x='attack_cat', data=data, order=sorted_attack_labels, palette=color_palette)

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.0f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.title('Distribution of Attack Categories')
plt.tight_layout()
plt.show()


# In[88]:


# Define the labels from your original list
labels = ["arp", "tcp", "udp", "other"]

# Calculate the counts of each protocol
protocol_counts = data['proto'].value_counts()

# Sort the labels and values based on the counts in descending order
sorted_labels = sorted(labels, key=lambda label: protocol_counts.get(label, 0), reverse=True)
sorted_values = np.array([protocol_counts.get(label, 0) for label in sorted_labels])

# Choose a color palette from seaborn
color_palette = sns.color_palette("gnuplot2")

# Create the bar chart using the chosen color palette
fig, ax = plt.subplots(figsize=(10, 6))
sns.barplot(x=sorted_labels, y=sorted_values, palette=color_palette, ax=ax)

# Add labels and title with larger font size
plt.xlabel("Protocols", fontsize=16)
plt.ylabel("Count", fontsize=16)
plt.title("Distribution of Protocols", fontsize=18)

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

# Rotate x-axis labels for better readability
ax.tick_params(axis='x', rotation=45)

# Show the bar chart
plt.tight_layout()
plt.show()


# In[89]:


import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Categorize attack categories
data["attack_cat"] = data["attack_cat"].apply(lambda x: "Attack" if x != "Normal" else "Normal")

# Set the style
sns.set(style="whitegrid")

# Grouping by state and attack category, and then summing the occurrences
grouped_spkts = data.groupby(["state", "attack_cat"]).size().reset_index(name="count")

# Filter for the states
selected_states = ["FIN", "INT", "CON", "RST", "REQ"]
selected_data = grouped_spkts[grouped_spkts["state"].isin(selected_states)]

# Create a bar plot for the selected states
plt.figure(figsize=(12, 8))
custom_palette = sns.color_palette("gnuplot2", n_colors=len(selected_states))
ax = sns.barplot(x="attack_cat", y="count", hue="state", data=selected_data, palette=custom_palette)
plt.xlabel("Attack Category")
plt.ylabel("Count")
plt.title("Attack v/s Normal for different TCP States")
plt.xticks(rotation=45)
plt.tight_layout()

plt.legend(title="State")

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.0f'), 
                (p.get_x() + p.get_width() / 2., p.get_height()), 
                ha = 'center', va = 'center', 
                xytext = (0, 9), 
                textcoords = 'offset points')

plt.show()


# In[90]:


import seaborn as sns
import matplotlib.pyplot as plt

plt.figure(figsize=(12, 6)) 

# Get the sorted order of states based on the count of attacks
state_order = data['state'].value_counts().index
ch1 = sns.countplot(x=data['state'], palette="nipy_spectral", order=state_order)
plt.title('Attack category by State')
plt.xlabel('State') 
plt.ylabel('Number of attacks on each State') 

# Adding data labels
for lab in ch1.containers:
    ch1.bar_label(lab, fmt='%d')  # Format the labels as integers

plt.xticks(rotation=90)  # Rotate x-axis labels for better readability
plt.show()



# In[133]:


# Group attack categories into "Normal" and "Attack"
data["attack_cat"] = data["attack_cat"].apply(lambda x: "Normal" if x == "Normal" else "Attack")

# Create a crosstab between service and attack_cat
crosstab = pd.crosstab(data["service"], data["attack_cat"])

# Create a stacked bar plot
sns.set(style="whitegrid")
plt.figure(figsize=(10, 6))
crosstab.plot(kind="bar", stacked=True, colormap="rainbow")
plt.xlabel("Service")
plt.ylabel("Count")
plt.title("Attack Categories by Service Type")
plt.xticks(rotation=45)
plt.tight_layout()
plt.legend(title="Attack Category")
# Calculate and display the counts as annotations
for i, category in enumerate(crosstab.columns):
    total = crosstab[category].sum()
    plt.annotate(f"{total}", xy=(i, total), ha="center", va="bottom")
plt.show()


# In[91]:



import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Assuming you have already loaded your data into the 'data' DataFrame

# Sort the data by 'dbytes' in descending order
data.sort_values(by='dbytes', ascending=False, inplace=True)

# Set the color palette to "bright"
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average dbytes grouped by attack categories
sns.barplot(x='attack_cat', y='dbytes', data=data, ci=None, ax=ax, order=data['attack_cat'].unique())
plt.title('Destination Bytes by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Bytes', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()


# In[92]:


import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Assuming you have already loaded your data into the 'data' DataFrame

# Sort the data by 'sbytes' in descending order
data.sort_values(by='sbytes', ascending=False, inplace=True)

# Set the color palette to "bright"
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average sbytes grouped by attack categories
sns.barplot(x='attack_cat', y='sbytes', data=data, ci=None, ax=ax, order=data['attack_cat'].unique())
plt.title('Source Bytes by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Bytes', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()


# In[93]:


# Map the "-" category to "No Service" for better visualization
data["service"] = data["service"].apply(lambda x: "No Service" if x == "-" else x)

# Create a crosstab between service and state
crosstab = pd.crosstab(data["service"], data["state"])

# Create a stacked bar plot
sns.set(style="whitegrid")
plt.figure(figsize=(10, 6))
crosstab.plot(kind="bar", stacked=True, colormap="Paired")
plt.xlabel("Service")
plt.ylabel("Count")
plt.title("Connection States by Service Type")
plt.xticks(rotation=45)
plt.tight_layout()
plt.legend(title="State")
plt.show()


# In[94]:


import seaborn as sns
import matplotlib.pyplot as plt
# Grouped bar plot for destination packets (dpkts)
plt.figure(figsize=(12, 8))
grouped_dpkts = data.groupby(["state", "attack_cat"])["dur"].sum().reset_index()
sns.barplot(x="state", y="dur", hue="attack_cat", data=grouped_dpkts,palette="gnuplot2")
plt.xlabel("State")
plt.ylabel("Duration in second")
plt.title("Total Duration in seconds by State and Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()

# Legend for attack_cat
plt.legend(title="Attack Category")

plt.show()


# In[95]:


# Set the color palette for the bar chart
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average spkts grouped by attack categories
sns.barplot(x='attack_cat', y='spkts', data=data, ci=None, ax=ax)
plt.title('Source Packets By Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Packet', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()

# Save the plot as a transparent PNG image
plt.savefig('plot.png', dpi=300, transparent=True)


# In[96]:


# Set the color palette for the bar chart
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average dpkts grouped by attack categories
sns.barplot(x='attack_cat', y='dpkts', data=data, ci=None, ax=ax)
plt.title('Destination Packets By Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Packet', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()

# Save the plot as a transparent PNG image
plt.savefig('plot.png', dpi=300, transparent=True)


# In[97]:


# the average source (spkts) and destination (dpkts) packet counts for different states.

# Set the style
sns.set(style="whitegrid")

# Grouped bar plot
plt.figure(figsize=(10, 6))
grouped = data.groupby("state").mean().reset_index()
melted = pd.melt(grouped, id_vars="state", value_vars=["spkts", "dpkts"])
custom_palette = sns.color_palette("gnuplot2", n_colors=len(data["state"].unique()))
sns.barplot(x="variable", y="value", hue="state", data=melted, palette=custom_palette)
plt.xlabel("Attribute")
plt.ylabel("Average Value")
plt.title("Average Packet size for source & destination by State")
plt.xticks(rotation=45)
plt.tight_layout()
plt.legend(title="State")
plt.show()


# In[98]:


# the average source (spkts) and destination (dpkts) packet counts for different service types.

# Map the "-" category to "No Service" for better visualization
data["service"] = data["service"].apply(lambda x: "No Service" if x == "-" else x)
# Set the style
sns.set(style="whitegrid")

# Grouped bar plot
plt.figure(figsize=(10, 6))
grouped = data.groupby("service").mean().reset_index()
melted = pd.melt(grouped, id_vars="service", value_vars=["spkts", "dpkts"])
custom_palette = sns.color_palette("gnuplot2", n_colors=len(data["service"].unique()))
sns.barplot(x="variable", y="value", hue="service", data=melted, palette=custom_palette)
plt.xlabel("Attribute")
plt.ylabel("Average Value")
plt.title("Average Packet and Byte Counts by Service Type")
plt.xticks(rotation=45)
plt.tight_layout()
plt.legend(title="Service")
plt.show()


# In[99]:


# Set the color palette for the bar chart
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average sjit grouped by attack categories
sns.barplot(x='attack_cat', y='sjit', data=data, ci=None, ax=ax)
plt.title('Source Jitter By Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Jitter', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()


# In[100]:


# Set the color palette for the bar chart
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average djit grouped by attack categories
sns.barplot(x='attack_cat', y='djit', data=data, ci=None, ax=ax)
plt.title('Destination Jitter By Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Jitter', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()


# In[101]:


import seaborn as sns
import matplotlib.pyplot as plt

# Set the color palette to "gnuplot2"
sns.set_palette("gnuplot2")

# Create a figure and axes
fig, ax = plt.subplots(figsize=(12, 8))
# Create a bar chart of average sttl grouped by attack categories
sns.barplot(x='attack_cat', y='sttl', data=data, ci=None, ax=ax)
plt.title('Source Time-To-Live By Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Time-To-Live', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()


# In[102]:


import seaborn as sns
import matplotlib.pyplot as plt

# Set the color palette to "gnuplot2"
sns.set_palette("gnuplot2")

# Create a figure and axes
fig, ax = plt.subplots(figsize=(12, 8))
# Create a bar chart of average dttl grouped by attack categories
sns.barplot(x='attack_cat', y='dttl', data=data, ci=None, ax=ax)
plt.title('Destination Time-To-Live By Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Time-To-Live', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')

plt.tight_layout()


# In[103]:


#a bar plot for the "trans_depth" variable grouped by the "attack_cat" variable

# Set the style
sns.set(style="whitegrid")

# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="trans_depth", data=data, ci=None,palette='viridis')
plt.xlabel("Attack Category")
plt.ylabel("Transaction Depth")
plt.title("Transaction Depth by Attack Category")
plt.tight_layout()

plt.show()


# In[104]:


# Set the style
sns.set(style="whitegrid")

# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_flw_http_mthd", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Average Count of Unique HTTP Methods")
plt.title("HTTP Methods by Attack Category")
plt.tight_layout()

plt.show()


# In[105]:


# Set the style
sns.set(style="whitegrid")

# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="is_ftp_login", data=data, ci=None,palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("FTP Login (1 = Yes, 0 = No)")
plt.title("FTP Login by Attack Category")
plt.tight_layout()

plt.show()


# In[106]:


# Create a DataFrame for the desired states
states_to_plot = ["FIN", "ECO", "INT", "CON","others"]
states_data = data[data["state"].isin(states_to_plot)]

# Grouped bar plot for source packets (spkts)
plt.figure(figsize=(12, 8))
grouped_spkts = states_data.groupby(["state", "attack_cat"])["synack"].sum().reset_index()
custom_palette = sns.color_palette("Set3", n_colors=len(states_data["state"].unique()))
sns.barplot(x="state", y="synack", hue="attack_cat", data=grouped_spkts, palette="nipy_spectral")
plt.xlabel("State")
plt.ylabel("SYN-ACK Flag Count")
plt.title("SYN-ACK Flag Count by State and Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()

# Legend for attack_cat
plt.legend(title="Attack Category")
plt.show()


# In[107]:


# a bar plot for the "is_sm_ips_ports" variable grouped by "attack_cat":
#The "is_sm_ips_ports" variable indicates whether the source or destination port is considered a "small" port (1) or not (0)
# Set the style
sns.set(style="whitegrid")

# Create a bar plot
plt.figure(figsize=(10, 6))
sns.countplot(x="is_sm_ips_ports", hue="attack_cat", data=data, palette="viridis")
plt.xlabel("is_sm_ips_ports")
plt.ylabel("Count")
plt.title(" is_sm_ips_ports by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()

# Legend
plt.legend(title="Attack Category")

plt.show()


# In[108]:


# the average source (spkts) and destination (dpkts) packet counts for different states.

# Set the style
sns.set(style="whitegrid")

# Grouped bar plot
plt.figure(figsize=(10, 6))
grouped = data.groupby("state").mean().reset_index()
melted = pd.melt(grouped, id_vars="state", value_vars=["sbytes", "dbytes"])
custom_palette = sns.color_palette("gnuplot2", n_colors=len(data["state"].unique()))
sns.barplot(x="variable", y="value", hue="state", data=melted, palette=custom_palette)
plt.xlabel("Attribute")
plt.ylabel("Average Value of Bytes")
plt.title("Average Byte Size for Source & Destination by State")
plt.xticks(rotation=45)
plt.tight_layout()
plt.legend(title="State")
plt.show()


# In[109]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average rate grouped by attack categories
sns.barplot(x='attack_cat', y='rate', data=data, ci=None, ax=ax)
plt.title('Rate v/s Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Rate', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()


# In[110]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average sload grouped by attack categories
sns.barplot(x='attack_cat', y='sload', data=data, ci=None, ax=ax)
plt.title('Source Load by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Load', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()
# Save the plot as a transparent PNG image
plt.savefig('plot.png', dpi=300, transparent=True)


# In[111]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average dload grouped by attack categories
sns.barplot(x='attack_cat', y='dload', data=data, ci=None, ax=ax)
plt.title('Destination Load by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Load', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()
# Save the plot as a transparent PNG image
plt.savefig('plot.png', dpi=300, transparent=True)


# In[112]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average sloss grouped by attack categories
sns.barplot(x='attack_cat', y='sloss', data=data, ci=None, ax=ax)
plt.title('Source Loss by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Loss', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()




# In[113]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average dloss grouped by attack categories
sns.barplot(x='attack_cat', y='dloss', data=data, ci=None, ax=ax)
plt.title('Destination Loss by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Loss', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()




# In[114]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average sinpkt grouped by attack categories
sns.barplot(x='attack_cat', y='sinpkt', data=data, ci=None, ax=ax)
plt.title('Source inter-arrival Packet by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Inter-arrival Packet', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()


# In[115]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average dinpkt grouped by attack categories
sns.barplot(x='attack_cat', y='dinpkt', data=data, ci=None, ax=ax)
plt.title('Destination inter-arrival Packet by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Inter-arrival Packet', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()


# In[116]:


# compare the interpacket arrival time distributions (sinpkt, dinpkt) for different service types,
# Map the "-" category to "No Service" for better visualization
data["service"] = data["service"].apply(lambda x: "No Service" if x == "-" else x)
# Set the style
sns.set(style="whitegrid")
# Melt the data for plotting
melted = pd.melt(data, id_vars=["service"], value_vars=["sinpkt", "dinpkt"])
# Create a simple plot without error bars
plt.figure(figsize=(10, 6))
sns.barplot(x="service", y="value", hue="variable", data=melted, ci=None,palette='viridis')
plt.xlabel("Service")
plt.ylabel("Interpacket Arrival Time")
plt.title("Interpacket Arrival Time by Service Type")
plt.xticks(rotation=45)
plt.tight_layout()
# Legend
plt.legend(title="Variable")
plt.show()


# In[117]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average swin grouped by attack categories
sns.barplot(x='attack_cat', y='swin', data=data, ci=None, ax=ax)
plt.title('Source Window by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source Window', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
               textcoords='offset points', color='black')
plt.tight_layout()


# In[118]:


# Set the color palette for the bar chart
sns.set_palette("bright")
# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')
# Create a bar chart of average dwin grouped by attack categories
sns.barplot(x='attack_cat', y='dwin', data=data, ci=None, ax=ax)
plt.title('Destination Window by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination Window', fontsize=14)
plt.xticks(rotation=45, color='black')
# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
               textcoords='offset points', color='black')
plt.tight_layout()


# In[119]:


#compare the TCP window size (swin, dwin) for different states
# Categorize attack categories
data["attack_cat"] = data["attack_cat"].apply(lambda x: "Attack" if x != "Normal" else "Normal")
# Set the style
sns.set(style="whitegrid")
# Melt the data for plotting
melted = pd.melt(data, id_vars=["attack_cat"], value_vars=["swin", "dwin"])
# Box plot for TCP window size
plt.figure(figsize=(12, 8))
sns.barplot(x="attack_cat", y="value", hue="variable", data=melted, ci=None, palette="nipy_spectral")
plt.xlabel("Attack Catgeory")
plt.ylabel("Average TCP Window Size ")
plt.title("Average TCP Window Size by Source and Destination by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
# Legend
plt.legend(title="Variable")
plt.show()


# In[120]:


# Map the "-" category to "No Service" for better visualization
data["service"] = data["service"].apply(lambda x: "No Service" if x == "-" else x)
# Set the style
sns.set(style="whitegrid")
# Melt the data for plotting
melted = pd.melt(data, id_vars=["service"], value_vars=["swin", "dwin"])
# Box plot for TCP window size
plt.figure(figsize=(12, 8))
sns.barplot(x="service", y="value", hue="variable", data=melted, ci=None,palette="viridis")
plt.xlabel("Service")
plt.ylabel("TCP Window Size ")
plt.title("TCP Window Size by Service Type")
plt.xticks(rotation=45)
plt.tight_layout()
# Legend
plt.legend(title="Variable")
plt.show()


# In[121]:


#compare the TCP window size (swin, dwin) for different states
# Set the style
sns.set(style="whitegrid")
# Melt the data for plotting
melted = pd.melt(data, id_vars=["state"], value_vars=["swin", "dwin"])
# Box plot for TCP window size
plt.figure(figsize=(12, 8))
sns.barplot(x="state", y="value", hue="variable", data=melted, ci=None, palette="nipy_spectral")
plt.xlabel("State")
plt.ylabel("TCP Window Size ")
plt.title("TCP Window Size by State")
plt.xticks(rotation=45)
plt.tight_layout()
# Legend
plt.legend(title="Variable")
plt.show()


# In[122]:


# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_ftp_cmd", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("FTP Commands Count")
plt.title("FTP Commands Count by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()



# In[123]:


# Set the color palette for the bar chart
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average stcpb grouped by attack categories
sns.barplot(x='attack_cat', y='stcpb', data=data, ci=None, ax=ax)
plt.title('Source TCP Base Sequence Number by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Source TCP Base Sequence Number', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()


# In[124]:


# Set the color palette for the bar chart
sns.set_palette("bright")

# Create a figure and axes with a customized background color
fig, ax = plt.subplots(figsize=(12, 8))
ax.set_facecolor('white')

# Create a bar chart of average dtcpb grouped by attack categories
sns.barplot(x='attack_cat', y='dtcpb', data=data, ci=None, ax=ax)
plt.title('Destination TCP Base Sequence Number by Attack Category', fontsize=18)
plt.xlabel('Attack Category', fontsize=14)
plt.ylabel('Destination  TCP Base Sequence Number', fontsize=14)
plt.xticks(rotation=45, color='black')

# Add data labels to the bars
for p in ax.patches:
    ax.annotate(format(p.get_height(), '.2f'),
                (p.get_x() + p.get_width() / 2., p.get_height()),
                ha='center', va='center',
                xytext=(0, 9),
                textcoords='offset points', color='black')
plt.tight_layout()


# In[125]:


# Set the style
sns.set(style="whitegrid")

# Create a bar plot
plt.figure(figsize=(10, 6))
ax = sns.barplot(x="attack_cat", y="ct_srv_src", data=data, ci=None, palette="viridis")

plt.xlabel("Attack Category")
plt.ylabel("Connection to Service Source Count")
plt.title("Connection to Service Source Count by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()



# In[126]:


# Calculate the total sum of connection destination long-term memory counts
total_counts = data.groupby("attack_cat")["ct_state_ttl"].sum()
total_sum = total_counts.sum()
# Calculate the percentage for each category
category_percentages = (total_counts / total_sum) * 100
# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
ax = sns.barplot(x="attack_cat", y="ct_state_ttl", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection State to Time Live Count")
plt.title("Connection State to Time Live Count by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
# Add percentage labels on top of each bar
for p, percentage in zip(ax.patches, category_percentages):
    height = p.get_height()
    ax.annotate(f'{percentage:.2f}%', (p.get_x() + p.get_width() / 2., height),
                ha='center', va='bottom')
plt.show()


# In[127]:


# Calculate the total sum of connection destination long-term memory counts
total_counts = data.groupby("attack_cat")["ct_dst_ltm"].sum()
total_sum = total_counts.sum()
# Calculate the percentage for each category
category_percentages = (total_counts / total_sum) * 100
# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
ax = sns.barplot(x="attack_cat", y="ct_dst_ltm", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection Destination Long-Term Memory")
plt.title("Connection Destination Long-Term Memory by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
# Add percentage labels on top of each bar
for p, percentage in zip(ax.patches, category_percentages):
    height = p.get_height()
    ax.annotate(f'{percentage:.2f}%', (p.get_x() + p.get_width() / 2., height),
                ha='center', va='bottom')
plt.show()


# In[128]:


# Calculate the total sum of connection destination long-term memory counts
total_counts = data.groupby("attack_cat")["ct_src_dport_ltm"].sum()
total_sum = total_counts.sum()
# Calculate the percentage for each category
category_percentages = (total_counts / total_sum) * 100
# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_src_dport_ltm", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection Source to Destination Port Long-Term Memory")
plt.title("Connection Source to Destination Port Long-Term Memory by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
# Add percentage labels on top of each bar
for p, percentage in zip(ax.patches, category_percentages):
    height = p.get_height()
    ax.annotate(f'{percentage:.2f}%', (p.get_x() + p.get_width() / 2., height),
                ha='center', va='bottom')
plt.show()


# In[129]:


# Calculate the total sum of connection destination long-term memory counts
total_counts = data.groupby("attack_cat")["ct_dst_sport_ltm"].sum()
total_sum = total_counts.sum()
# Calculate the percentage for each category
category_percentages = (total_counts / total_sum) * 100
# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_dst_sport_ltm", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection Destination to Source Port Long-Term Memory ")
plt.title("Connection Destination to Source Port Long-Term Memory by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# In[130]:


# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_src_ltm", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection Source Long-Term Memory")
plt.title("Connection Source Long-Term Memory by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# In[131]:


# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_src_ltm", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection Source Long-Term Memory")
plt.title("Connection Source Long-Term Memory by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# In[132]:


# Set the style
sns.set(style="whitegrid")
# Create a bar plot
plt.figure(figsize=(10, 6))
sns.barplot(x="attack_cat", y="ct_srv_dst", data=data, ci=None, palette="viridis")
plt.xlabel("Attack Category")
plt.ylabel("Connection Service to Destination Count")
plt.title("Connection Service to Destination Count by Attack Category")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# In[ ]:





# In[ ]:





# In[ ]:




