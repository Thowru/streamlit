# 필요한 라이브러리 가져오기
import streamlit as st
import pandas as pd
from datetime import datetime

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

# Streamlit 앱
def main():
    st.title('로그 데이터 처리 앱')

    # 파일 업로드
    uploaded_file = st.file_uploader("CSV 파일 선택", type="csv")

    if uploaded_file is not None:
        # CSV 파일 읽기
        log_df = pd.read_csv(uploaded_file)

        # 로그 데이터 처리
        processed_log_df = process_log_data(log_df)

        # 처리된 데이터 표시
        st.write("처리된 로그 데이터:")
        st.write(processed_log_df)

        # 처리된 데이터를 새로운 CSV 파일로 저장
        processed_file_path = 'processed_file.csv'
        processed_log_df.to_csv(processed_file_path, index=False)

        # 처리된 파일을 다운로드할 수 있는 링크 제공
        st.markdown(f"처리된 데이터 다운로드: [처리된 파일]({processed_file_path})")

from sklearn.ensemble import IsolationForest  # 이상탐지 모델 예시 (다른 모델로 대체 가능)
from sklearn.model_selection import train_test_split
from sklearn import linear_model, tree, neighbors
from sklearn import preprocessing
from sklearn.cluster import KMeans
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from joblib import dump, load

# 전처리된 데이터 로드
processed_file_path = 'train_processed.csv'
processed_log_df = pd.read_csv(processed_file_path)

# 이상탐지 모델 학습
# 여기에서는 Isolation Forest를 사용하였습니다. 다른 이상탐지 모델을 사용할 수도 있습니다.
model = IsolationForest(contamination=0.01)  # contamination은 이상치 비율을 나타냅니다.
model.fit(processed_log_df[['method_cnt', 'method_post', 'status_major', 'status_404', 'bytes_avg', 'bytes_std']])

# Streamlit 앱
def main():
    st.title('이상탐지 앱')

    # 전처리된 데이터 표시
    st.write("전처리된 로그 데이터:")
    st.write(processed_log_df)

    # 이상탐지 결과 예측
    predictions = model.predict(processed_log_df[['method_cnt', 'method_post', 'status_major', 'status_404', 'bytes_avg', 'bytes_std']])
    processed_log_df['anomaly'] = (predictions == -1)  # -1은 이상치를 나타냅니다.

    # 이상치 시각화
    st.write("이상치 여부:")
    st.write(processed_log_df[['anomaly']])

    # 이상치에 대한 상세 정보 표시
    anomaly_details = processed_log_df[processed_log_df['anomaly']]
    st.write("이상치 상세 정보:")
    st.write(anomaly_details)

if __name__ == '__main__':
    main()
