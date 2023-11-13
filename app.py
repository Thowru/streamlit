import streamlit as st
import pandas as pd
from sklearn.cluster import KMeans
from sklearn import preprocessing
import pickle

# 로그 데이터 처리 함수
def process_log_data(log_df):
    log_df.drop(columns='timestamp', inplace=True)
    log_df['Timestamp'] = log_df['message'].str.extract(r'(\d+/\w+/\d+\d+:\d+:\d+:\d+)')
    log_df['Timestamp'] = pd.to_datetime(log_df['Timestamp'], format='%d/%b/%Y:%H:%M:%S').dt.strftime('%Y-%m-%d %H:%M:%S')
    log_df['Host'] = log_df['message'].str.extract(r'(\d+.\d+.\d+.\d+)')
    log_df[['Method', 'Path']] = log_df['message'].str.extract(r'(HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|POST|GET)\s+(.?)\s+HTTP')
    log_df['Protocol'] = log_df['message'].str.extract(r'(HTTP/\d+.\d+)')
    log_df['Status'] = log_df['message'].str.extract(r'(\d+)\s+\d+')
    log_df['Bytes'] = log_df['message'].str.extract(r'\d+\s+(\d+)')
    log_df['UA'] = log_df['message'].str.extract(r'(Mozilla.+537.36)')
    selected_log_df = log_df[log_df['Method'].isna() & log_df['Protocol'].isna()]
    log_df['Payload'] = selected_log_df['message'].str.extract(r']{1}\s+"(.)" \d+')
    log_df['Referer'] = log_df['message'].str.extract(r'."(http[s]?://.?)"')
    log_df.drop(columns='message', inplace=True)
    log_df = log_df[['Timestamp','Method','Protocol','Status','Referer','Path','Host','UA','Payload','Bytes']]
    return log_df

# 특성 추출 함수
def feature_extract(df):
    df['method_cnt'] = df['Method'].nunique()
    df['method_post'] = df['Method'].apply(lambda x: 1 if x == 'POST' else 0)
    df['protocol_1_0'] = df['Protocol'].apply(lambda x: True if 'HTTP/1.0' in x else False)
    df['status_major'] = df['Status'].apply(lambda x: 1 if x in ['200', '301', '302'] else 0)
    df['status_404'] = df['Status'].apply(lambda x: 1 if x == '404' else 0)
    df['status_499'] = df['Status'].apply(lambda x: True if x == '499' else False)
    df['status_cnt'] = df['Status'].nunique()
    df['path_same'] = df.groupby('Host')['Path'].transform(lambda x: x.value_counts().iloc[0] / len(x))
    df['path_xmlrpc'] = df['Path'].apply(lambda x: 1 if 'xmlrpc.php' in x else 0)
    df['ua_cnt'] = df.groupby('Host')['UA'].transform('nunique')
    df['has_payload'] = df['Payload'].apply(lambda x: True if x != '-' else False)
    df['bytes_avg'] = df.groupby('Host')['Bytes'].transform('mean')
    df['bytes_std'] = df.groupby('Host')['Bytes'].transform('std')
    return df

# 이상 탐지 함수
def anomaly_detection(df):
    # 특성 선택
    chosen_data = df[['method_cnt', 'method_post', 'protocol_1_0', 'status_major', 'status_404', 'status_499',
                      'status_cnt', 'path_same', 'path_xmlrpc', 'ua_cnt', 'has_payload', 'bytes_avg', 'bytes_std']]

    # Min-Max 스케일링
    min_max_scaler = preprocessing.MinMaxScaler()
    np_scaled = min_max_scaler.fit_transform(chosen_data)
    chosen_data = pd.DataFrame(np_scaled, columns=chosen_data.columns)

    # 클러스터링
    cluster_model = KMeans(n_clusters=2)  # 예시로 2개의 클러스터 사용
    df['cluster'] = cluster_model.fit_predict(chosen_data)

    # 클러스터 결과 리턴
    return df

# Streamlit 앱
def main():
    st.title('로그 데이터 처리 및 이상 탐지 앱')

    # 파일 업로드
    uploaded_file = st.file_uploader("CSV 파일 선택", type="csv")

    if uploaded_file is not None:
        # CSV 파일 읽기
        log_df = pd.read_csv(uploaded_file)

        # 로그 데이터 처리
        processed_log_df = process_log_data(log_df)

        # 특성 추출
        feature_df = feature_extract(processed_log_df)

        # 이상 탐지
        anomaly_df = anomaly_detection(feature_df)

        # 처리된 데이터 표시
        st.write("처리된 로그 데이터:")
        st.write(anomaly_df)

        # 처리된 데이터를 새로운 CSV 파일로 저장
        processed_file_path = 'processed_file.csv'
        anomaly_df.to_csv(processed_file_path, index=False)

        # 처리된 파일을 다운로드할 수 있는 링크 제공
        st.markdown(f"처리된 데이터 다운로드: [처리된 파일]({processed_file_path})")

if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()
