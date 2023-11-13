import streamlit as st
import pandas as pd
import time
import re
# 파일 업로드 버튼 (업로드 기능)
file = st.file_uploader("파일 선택(csv or excel)", type=['csv', 'xls', 'xlsx'])

# 파일이 정상 업로드 된 경우
# if file is not None:
#     # 파일 읽기
#     df = pd.read_csv(file)
#     # 출력
#     st.dataframe(df)

time.sleep(3)

# Excel or CSV 확장자를 구분하여 출력하는 경우
if file is not None:
    ext = file.name.split('.')[-1]
    if ext == 'csv':
        # 파일 읽기
        log_df = pd.read_csv(file)
        # 출력
        st.dataframe(log_df)
    elif 'xls' in ext:
        # 엑셀 로드
        log_df = pd.read_excel(file, engine='openpyxl')
        # 출력
        st.dataframe(log_df)
        
log_df.drop(columns='timestamp', inplace=True)
log_df['Timestamp'] = log_df['message'].str.extract(r'(\d+/\w+/\d+\d+\:\d+\:\d+\:\d+)')

from datetime import datetime
log_df['Timestamp'] = pd.to_datetime(log_df['Timestamp'], format='%d/%b/%Y:%H:%M:%S').dt.strftime('%Y-%m-%d %H:%M:%S')

log_df['Host'] = log_df['message'].str.extract(r'(\d+\.\d+\.\d+\.\d+)')

# log_df['method'] = log_df['message'].str.extract(r'(HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|POST|GET)')

log_df[['Method', 'Path']] = log_df['message'].str.extract(r'(HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|POST|GET)\s+(.*?)\s+HTTP')

log_df['Protocol'] = log_df['message'].str.extract(r'(HTTP\/\d+\.\d+)')

log_df['Status'] = log_df['message'].str.extract(r'(\d+)\s+\d+')

log_df['Bytes'] = log_df['message'].str.extract(r'\d+\s+(\d+)')

log_df['UA'] = log_df['message'].str.extract(r'(Mozilla.+537.36)')

selected_log_df = log_df[log_df['Method'].isna() & log_df['Protocol'].isna()]

log_df['Palyload'] = selected_log_df['message'].str.extract(r'\]{1}\s+"(.*)" \d+')

log_df['Referer'] = log_df['message'].str.extract(r'.*"(http[s]?://.*?)"')

log_df.drop(columns='message', inplace=True)

log_df = log_df[['Timestamp','Method','Protocol','Status','Referer','Path','Host','UA','Palyload','Bytes']]

st.datafram(log_df)
