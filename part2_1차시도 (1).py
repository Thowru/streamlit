import streamlit as st
import pandas as pd
from io import StringIO
import re
import requests
import json
import ipaddress
import csv
#import matplotlib.pyplot as plt
st. set_page_config(layout="wide",page_title="Log Analyser", page_icon="🪵")
st.caption("")
st.title("Log Analyser 🪵")
def checkIPs(ip):  # gets the data for a single IP address
    submissionURL = 'http://ip-api.com/json/' + str(ip) + '?fields=status,message,countryCode,isp,org,as,mobile,proxy,hosting,query'
    r = json.loads(str(requests.post(submissionURL).text))

    return r
def logLineToDict(line):
    conf = '$remote_addr - $remote_user [$time_local] "$request_method $request $httpversion" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
    regex = ''.join(
        '(?P<' + g + '>.*?)' if g else re.escape(c)
        for g, c in re.findall(r'\$(\w+)|(.)', conf))

    m = re.match(regex,line)
    return m.groupdict()


st.write("Once you've uploaded a log file, the app will check for Googlebot by matching against the official Google IP ranges. It will also let you download just the Googlebot hits (currently all types of Googlebot, including Ads right now) Also shows a summary of most crawled pages, highest frequency IP addresses. It uses http://ip-api.com to check the hosting and country data of the top 10 ips in the list.")




# Allow the user to upload the log file
uploaded_file = st.file_uploader("Upload your log file")

if uploaded_file is not None:
    logs = []
    for thefile in uploaded_file:
        decoded_logs = StringIO(thefile.decode("utf-8"))
        for line in decoded_logs:
             logs.append(logLineToDict(line))
    logs_df = pd.DataFrame(logs)
    logs_df["Googlebot Confirmed"] = ""

    # URL of the list of IPs
    url = "https://www.gstatic.com/ipranges/goog.json"

    # Get the list of IPs
    response = requests.get(url)
    response.raise_for_status()
    data = json.loads(response.text)
    google_ips = json.loads(response.text)["prefixes"]

    ipv4_ips = [prefix["ipv4Prefix"] for prefix in google_ips if "ipv4Prefix" in prefix]
    ipv6_ips = [prefix["ipv6Prefix"] for prefix in google_ips if "ipv6Prefix" in prefix]
    google_ip_ranges = []
    google_ip_ranges.extend(ipv4_ips)
    google_ip_ranges.extend(ipv6_ips)
    # Loop through each IP address in logs_df
    with st.spinner('Checking logs and verifying...'):
        for index, row in logs_df.iterrows():
            ip = row['remote_addr']
            googlebot_confirmed = 'N'

            # Loop through each IP range in google_ip_ranges
            for ip_range in google_ip_ranges:
                # Create an IPv4Network or IPv6Network object
                network = ipaddress.ip_network(ip_range)

                # Create an IPv4Address or IPv6Address object
                address = ipaddress.ip_address(ip)

                # Check if the IP address is in the IP range
                if address in network:
                    googlebot_confirmed = 'Y'
                    break

            # Set the value of the "Googlebot Confirmed" column
            logs_df.loc[index, "Googlebot Confirmed"] = googlebot_confirmed

        search_term = st.text_input("Enter IP to filter")
        initialTable = st.dataframe(logs_df, use_container_width=True)
    filtered_logs = logs_df.loc[logs_df["remote_addr"].str.contains(search_term)]

    initialTable.empty()
    st.dataframe(filtered_logs)





    # Add a function to download the filtered logs as a CSV file
    def download_google_csv():
        # Get the lines of the DataFrame where "Googlebot Confirmed" is "Y"
        filtered_logs = logs_df.loc[logs_df["Googlebot Confirmed"] == "Y"]

        filtered_logs = filtered_logs.to_csv().encode('utf-8')

        st.download_button(
            label="Download data as CSV",
            data=filtered_logs,
            file_name='filtered_logs.csv',
            mime='text/csv',
        )

    def download_csv():
        # Get the lines of the DataFrame where "Googlebot Confirmed" is "Y"
        csvLogs = logs_df
        csvLogs = csvLogs.to_csv().encode('utf-8')

        st.download_button(
            label="Download data as CSV",
            data=csvLogs,
            file_name='raw_logs.csv',
            mime='text/csv',
        )


    st.subheader("Download Raw Logs as a CSV")
    download_csv()

    # Add a button to download the filtered logs as a CSV file
    if not filtered_logs.empty:
        st.subheader("Download Googlebot Log Entries")
        download_google_csv()

    # Get a list of the IP addresses sorted by the number of times they appear in the logs_df DataFrame
    ip_counts = logs_df["remote_addr"].value_counts()


    # Loop through the top 10 IP addresses
    # Get a list of the IP addresses sorted by the number of times they appear in the logs_df DataFrame
    ip_counts = logs_df["remote_addr"].value_counts()
    # Get the top 10 IP addresses from the list
    top_10_ips_counts = ip_counts.head(10)
    top_10_ips = top_10_ips_counts.keys().tolist()

    # Create a new DataFrame containing only the relevant data
    top_10_df = pd.DataFrame(columns=["IP", "Count", "Country Code", "Organisation", "Hosting", "AS"])

    # Loop through the top 10 IP addresses
    for ip in top_10_ips:
        # Get the data for a single IP address
        ip_data = checkIPs(ip)

        # Add a row to the top_10_df DataFrame with the relevant values
        top_10_df = top_10_df.append(
            {"IP": ip, "Count": ip_counts[ip], "Country Code": ip_data["countryCode"], "Organisation": ip_data["org"],
             "Hosting": ip_data["hosting"], "AS": ip_data["as"]}, ignore_index=True)

    # Merge the top 10 IP addresses from the ip_counts DataFrame with the data for each IP address from the logs_df DataFrame
    top_10_ips_df = ip_counts.to_frame().merge(top_10_df, left_index=True, right_on="IP")

    top_10_ips_df.drop('remote_addr', inplace=True, axis=1)

    # Display the top 10 IP addresses DataFrame
    st.subheader('Top 10 IPs with their ISP/Hosting Data')
    st.dataframe(top_10_ips_df)

    # Get the lines of the DataFrame where "Googlebot Confirmed" is "Y"
    googlebot_confirmed_logs = logs_df.loc[logs_df["Googlebot Confirmed"] == "Y"]

    # Get the top 10 most frequent request URLs where "Googlebot Confirmed" is "Y"
    top_request_urls = googlebot_confirmed_logs["request"].value_counts()[:50]

    # Display the top 10 most frequent request URLs where "Googlebot Confirmed" is "Y"
    st.subheader("Top 50 Most Frequent Crawled URLs by Google")
    st.write(top_request_urls)

    # Get top 10 most frequent User Agents
    top_user_agents = logs_df["http_user_agent"].value_counts()[:10]

    # Display the top 10 most frequent User Agents
    st.subheader("Top 10 Most Frequent User Agents")
    st.write(top_user_agents)

    # # Convert the timestamp column to datetime objects
    # logs_df['time_local'] = pd.to_datetime(logs_df['time_local'], format='%d/%b/%Y:%H:%M:%S +0000')
    # log_counts = logs_df['time_local'].value_counts()
    #
    # log_counts.plot(kind='line')
    #
    # # Plot the chart using matplotlib and display it in Streamlit
    # plt.tight_layout()
    # st.pyplot()
