# 필요한 라이브러리 가져오기
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# 로그 데이터를 처리하는 함수
def process_log_data(log_df):
    log_df.drop(columns='timestamp', inplace=True)
    log_df['Timestamp'] = log_df['message'].str.extract(r'(\d+/\w+/\d+\d+\:\d+\:\d+\:\d+)')
    log_df['Timestamp'] = pd.to_datetime(log_df['Timestamp'], format='%d/%b/%Y:%H:%M:%S').dt.strftime('%Y-%m-%d %H:%M:%S')
    log_df['Host'] = log_df['message'].str.extract(r'(\d+\.\d+\.\d+\.\d+)')
    log_df[['Method', 'Path']] = log_df['message'].str.extract(r'(HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|POST|GET)\s+(.*?)\s+HTTP')
    log_df['Protocol'] = log_df['message'].str.extract(r'(HTTP\/\d+\.\d+)')
    log_df['Status'] = log_df['message'].str.extract(r'(\d+)\s+\d+')
    log_df['Bytes'] = log_df['message'].str.extract(r'\d+\s+(\d+)')
    log_df['UA'] = log_df['message'].str.extract(r'(Mozilla.+537.36)')
    selected_log_df = log_df[log_df['Method'].isna() & log_df['Protocol'].isna()]
    log_df['Payload'] = selected_log_df['message'].str.extract(r'\]{1}\s+"(.*)" \d+')
    log_df['Referer'] = log_df['message'].str.extract(r'.*"(http[s]?://.*?)"')
    log_df.drop(columns='message', inplace=True)
    log_df = log_df[['Timestamp','Method','Protocol','Status','Referer','Path','Host','UA','Payload','Bytes']]
    return log_df

# Feature Engineering Refactoring
def feature_extract(df):
    df['method_cnt'] = 0.0
    df['method_post'] = 0.0
    df['protocol_1_0'] = False
    df['status_major'] = 0.0
    df['status_404'] = 0.0
    df['status_499'] = False
    df['status_cnt'] = 0.0
    df['path_same'] = 0.0
    df['path_xmlrpc'] = True
    df['ua_cnt'] = 0.0
    df['has_payload'] = False
    df['bytes_avg'] = 0.0
    df['bytes_std'] = 0.0
    cnt = 0

    for entity in df.index.values:
        if cnt % 500 == 0:  #진행과정 파악을 위한 로그
            print(cnt)

        group = df[df['Host']==entity]

        # 사용한 Method의 수
        method_cnt = group['Method'].nunique()
        df.loc[entity, 'method_cnt'] = method_cnt

        # 사용한 Method중 Post의 비율
        method_post_percent = len(group[group['Method']=='POST']) / float(len(group)) if len(group) > 0 else 0
        df.loc[entity, 'method_post'] = method_post_percent


        # Protocol 1.0 사용여부
        use_1_0 = True if len(group[group['Protocol']=='HTTP/1.0']) > 0 else False
        df.loc[entity, 'protocol_1_0'] = use_1_0

        # 정상(200, 301, 302) Status 비율
        status_major_percent = len(group[group['Status'].isin(['200', '301', '302'])]) / float(len(group))
        df.loc[entity, 'status_major'] = status_major_percent

        # 404 Status 비율
        status_404_percent = len(group[group['Status'].isin(['404'])]) / float(len(group))
        df.loc[entity, 'status_404'] = status_404_percent

        # 499 Status 포함여부
        has_499 = True if len(group[group['Status']=='499']) > 0 else False
        df.loc[entity, 'status_499'] = has_499

        # Status 종류 (Scanner 등은 Status가 다양할 수 있음)
        status_cnt = group['Status'].nunique()
        df.loc[entity, 'status_cnt'] = status_cnt

        # 같은 Path 반복적 접근 여부
        top1_path_cnt = group['Path'].value_counts()[0]
        df.loc[entity, 'path_same'] = float(top1_path_cnt / len(group))

        # /xmlrpc.php 접근 비율
        path_xmlrpc = len(group[group['Path'].str.contains('xmlrpc.php')==True]) / float(len(group))
        df.loc[entity, 'path_xmlrpc'] = path_xmlrpc

        # User agent를 바꾸는 경우
        df.loc[entity, 'ua_cnt'] = group['UA'].nunique()

        # Payload가 존재하는 경우
        has_payload = []
        if len(group[group['Payload'] != '-']) > 0:
            has_payload.append(True)
        else:
            has_payload.append(False)
        df.loc[entity, 'has_payload'] = has_payload

        # Bytes의 평균 / 분산
        df.loc[entity, 'bytes_avg'] = np.mean(group['Bytes'])
        df.loc[entity, 'bytes_std'] = np.std(group['Bytes'])

        cnt = cnt + 1
    return df

# Streamlit 앱
def main():
    st.title('로그 데이터 처리 및 이상탐지 앱')

    # 파일 업로드
    uploaded_file = st.file_uploader("CSV 파일 선택", type="csv")

    if uploaded_file is not None:
        # CSV 파일 읽기
        log_df = pd.read_csv(uploaded_file)

        # 로그 데이터 처리
        processed_log_df = process_log_data(log_df)

        # 전처리된 데이터에 피처 엔지니어링 적용
        processed_log_df = feature_extract(processed_log_df)

        # 이상탐지 모델 학습
        model = IsolationForest(contamination=0.01)  # contamination은 이상치 비율을 나타냅니다.
        model.fit(processed_log_df[['method_cnt', 'method_post', 'status_major', 'status_404', 'bytes_avg', 'bytes_std']])

        # 이상탐지 결과 예측
        predictions = model.predict(processed_log_df[['method_cnt', 'method_post', 'status_major', 'status_404', 'bytes_avg', 'bytes_std']])
        processed_log_df['anomaly'] = (predictions == -1)  # -1은 이상치를 나타냅니다.

        # 처리된 데이터 및 이상치 시각화
        st.write("전처리 및 이상탐지 결과:")
        st.write(processed_log_df[['Timestamp','Method','Protocol','Status','Referer','Path','Host','UA','Payload','Bytes', 'anomaly']])

        # 이상치에 대한 상세 정보 표시
        anomaly_details = processed_log_df[processed_log_df['anomaly']]
        st.write("이상치 상세 정보:")
        st.write(anomaly_details)

if __name__ == '__main__':
    main()
