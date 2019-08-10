#!/usr/bin/env python
# coding: utf-8

# In[2]:


import matplotlib.pyplot as plt
import pandas as pd


# In[3]: Read in miari and list of infected ips

mirai_data = pd.read_csv("/Users/daniel/Desktop/sideProjects/jacek/mirai_enriched_2018_07_03_2019.csv")
infected_ips = pd.read_csv("/Users/daniel/Desktop/sideProjects/jacek/results/all_infected_copy.csv")

# drop duplicates from mirai ?
mirai_data = mirai_data.drop_duplicates(subset=['ip'])
mirai_infected = mirai_data[mirai_data["ip"].isin(infected_ips["infected"])]

# could do this directly in the report
infected_group_by_country = mirai_infected.groupby(by=['country'])
infected_group_by_prefix = mirai_infected.groupby(by=['prefix'])
infected_group_by_asn = mirai_infected.groupby(by=['asn'])


# In[8]:


mirai_count = infected_group_by_asn.count()
print(mirai_count.sort_values(by=['ip'], ascending=False).head(10))


# In[10]:


mirai_country_plot_data = mirai_count.sort_values(by=['ip'], ascending=False).iloc[:,0]
print(mirai_country_plot_data.head(5))


# In[12]:


mirai_country_plot_data.head(10).plot(title="Number of infected devices by asn", grid=True, kind='bar')
plt.tight_layout()

plt.show()

plt.clf()
plt.close()

# In[13]:




# In[15]:


mirai_data["fseen"] = pd.to_datetime(mirai_data["fseen"], infer_datetime_format=False)
mirai_data["lseen"] = pd.to_datetime(mirai_data["lseen"], infer_datetime_format=False)


# In[16]:


print(mirai_data['fseen'].head(5))


# In[17]:


print(mirai_data['lseen'].head(5))


# In[18]:


c_diff = mirai_data['lseen'] - mirai_data['fseen']


# In[35]:


c_diff.sort_values(ascending=False).describe()
#c_diff = pd.DataFrame({"time":c_diff.sort_values(ascending=False)})


# In[20]:



_c_diff = pd.DataFrame({"time":c_diff.sort_values(ascending=False)})
_c_diff.head(10)


# In[21]:


_c_diff = _c_diff[_c_diff["time"] != pd.Timedelta('0 days 00:00:00')]


# In[22]:


_c_diff.head(5)


# In[23]:


_c_diff.describe()


# In[166]:


#_c_diff.fillna(pd.Timedelta('0 days 00:00:00')).plot.kde()


# In[39]:
"""

(_c_diff["time"] / pd.Timedelta(hours=1)).plot(kind='hist', bins=range(0, 200, 5), title="Infected by duration grouped in 5h bins")

plt.tight_layout()

plt.show()
plt.clf()
plt.close()

(_c_diff["time"] / pd.Timedelta(hours=1)).plot(kind='hist', bins=range(0, 200, 2), title="Infected by duration grouped in 2h bins")
plt.tight_layout()

plt.show()
plt.clf()
plt.close()




# In[40]:


(_c_diff["time"] / pd.Timedelta(hours=1)).plot(kind='hist', bins=range(1, 200, 5), title="Infected by duration grouped in 5h bins")
plt.tight_layout()

plt.show()
plt.clf()
plt.close()

(_c_diff["time"] / pd.Timedelta(hours=1)).plot(kind='hist', bins=range(0, 200, 2), title="Infected by duration grouped in 2h bins")
plt.tight_layout()

plt.show()
plt.clf()
plt.close()




# In[42]:


#(_c_diff["time"] / pd.Timedelta(hours=1)).plot.kde()


# In[58]:
"""

(_c_diff["time"] / pd.Timedelta(hours=1)).plot(kind="kde", ind=range(0,480,2), title="Density by duration").set_xlabel("Hours")
plt.tight_layout()

plt.show()
plt.clf()
plt.close()


# In[ ]:




