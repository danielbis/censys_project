This code is used to analyze Mirai, a malware that turns networked devices running Linux into remotely controlled bots
that can be used as part of a botnet in large-scale network attacks. It primarily targets online consumer devices
such as IP cameras and home routers.

Overview:
The package consists of four files. 
- config.py defines constants and paths to directories used across the package.
- loaders.py contains methods used to load and export the data. 
- plot_methods.py contains methods used to visualize the data using pandas and pyplot libraires, popular and easy to use
	tools for data analysis and visualization. 
- process_data.py is the main file containing methods doing most of the analysis, calling methods from the packages above. 


Details:

Initially, the method load_censys_ips (defined in the loaders file) loads the censys data into the RAM, file by file, storing ips which appeared in the censys data with port 23 or 2323. A variable of type set is used which guranatees that every IP stored is unique, therefore if IP appeared in the censys data more than once, we store only one copy of it. In the same way, load_censys_ips stores sets of ips with banners and without banners separately. Finally, a dictionary (hash table) mapping ips to their banners is created, also stroing only one copy of each IP, even if IP appeared in the dataset more than once. Therefore, we are able to obtain the number of unique IPs with port 23/2323, number of entries with other ports, number of entries with banner and number of entries without banners in the Censys dataset. 

Then, function generate_report is called. It executes multiple helper functions, processes data and stores results. Details below.

	First, we load data from Mirai dataset, line by line, storing ips which appeared in the dataset with port 23 or 2323 and on or past the December 4th 2018. A variable of type set is used which guranatees that every IP stored is unique, therefore if IP appeared in the mirai data more than once, we store only one copy of it. 

	Then, an intersection of two sets is calculated, returning a set of IPs which appeared in both Mirai and Censys with port 23 or 2323 and on or past the December 4th 2018. From now on we reference to that intersection as to the infected IPs.

	Next, method get_counts is executed. It is used to analyse the distribution of infected devices among the countries, ASN numbers and IP prefixes. It returns three different mappings corresponding to:
		- a country and the number unique infected IPs active in that country
		- an ASN and the number unique infected IPs active under that ASN
		- a prefix and the number of unique infected IPs with that prefix 

	Function infected_banners_stats returns the number of infected IPs with a banner and without a banner. 

	Function group_by_banners creates a mapping (hash table) of a banner and a list of unique IPs which appeared with that banner in the Censys dataset (there is no banners in Mirai). In short, it creates and exports to a csv file mappings banner --> list of unique IPs with that banner

	Then, method count_ports is executed. It exports the mapping (hash table) of ports and the number of unique infected IPs in Mirai dataset with that port. Note that the same IP may appear in Mirai multiple times, each time with different port. Therefore, some of the port counts does not need to equal the number of infected IPs. 

	After that, method group_by is executed. It used to examine if the same infected IP was active in more than one country or under more than once ASN number. First, this function exports the mapping (hash table) of IP and a list of unique countries where that IP occured. Then it is executed again, this time to export the mapping (hash table) of IP and a list of unique ASN numbers under which that IP occured.

	After that, the generate_report method runs a series of export functions which saves our statistics to the disk for further analysis and evaluation. 


After generate_report, we call load_data_and_count_devices method. We wanted a this function to work in isolation from the above methods so that all the steps are not repeated every time we want to run load_data_and_count_devices. Therefore,  load_data_and_count_devices loads mirai dataset again and calculates the intersection of two sets (unique Censys IPs and ips which appeared in the Mirai dataset with port 23 or 2323 and on or past the December 4th 2018), which we refer as to infected IPs again. 

Then function count_devices is called. It attempts to count the number of occurances of specific devices in the set of infected IPs. For that purpose, we try to laverage the description field from Censys dataset, as it often contains the device name. 
For each entry, in every file in the list of Censys files, we check if the entry is contained in the set of infected IPs. Additionaly, if the IP is already accounted for once, we do not count it again, even if it appears in the censys data multiple times, to avoid counting the same device multiple times. However, it turns out that a lot of entries in censys do not have the description field.




