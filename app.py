import streamlit as st
import pandas as pd
from datetime import datetime
import streamlit as st
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn import preprocessing
import pickle
from sklearn.decomposition import PCA
import seaborn as sns
import matplotlib.pyplot as plt

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
    df['protocol_1_0'] = df['Protocol'].apply(lambda x: True if pd.notna(x) and 'HTTP/1.0' in x else False)
    df['status_major'] = df['Status'].apply(lambda x: 1 if x in ['200', '301', '302'] else 0)
    df['status_404'] = df['Status'].apply(lambda x: 1 if x == '404' else 0)
    df['status_499'] = df['Status'].apply(lambda x: True if x == '499' else False)
    df['status_cnt'] = df['Status'].nunique()

    # 수정된 부분: 그룹 크기가 0이거나 NaN인 경우 0으로 설정
    df['path_same'] = df.groupby('Host')['Path'].transform(lambda x: x.value_counts().iloc[0] / len(x) if len(x) > 0 else 0)

    df['path_xmlrpc'] = df['Path'].apply(lambda x: 1 if 'xmlrpc.php' in x else 0)
    df['ua_cnt'] = df.groupby('Host')['UA'].transform('nunique')
    df['has_payload'] = df['Payload'].apply(lambda x: True if x != '-' else False)
    df['bytes_avg'] = df.groupby('Host')['Bytes'].transform('mean')
    df['bytes_std'] = df.groupby('Host')['Bytes'].transform('std')
    return df
# 이상 탐지 함수
def anomaly_detection(df):
    # Feature Engineering 및 전처리 (이상 탐지 모델에 사용될 특성 선택 및 스케일링)
    chosen_data = df[['method_cnt', 'method_post', 'protocol_1_0', 'status_major', 'status_404', 'status_499',
                      'status_cnt', 'path_same', 'path_xmlrpc', 'ua_cnt', 'has_payload', 'bytes_avg', 'bytes_std']]

    min_max_scaler = preprocessing.MinMaxScaler()
    np_scaled = min_max_scaler.fit_transform(chosen_data)
    chosen_data = pd.DataFrame(np_scaled, columns=chosen_data.columns)

    # 클러스터링 모델 불러오기
    with open('anomaly_entities_kmeans.pkl', 'rb') as f:
        cluster_model = pickle.load(f)

    # 클러스터 할당
    df['cluster'] = cluster_model.predict(chosen_data)

    return df

# 이상 탐지 결과 시각화 함수
def visualize_anomaly(df):
    tsne = PCA(n_components=2)
    tsne_results = tsne.fit_transform(chosen_data)

    df['tsne-2d-one'] = tsne_results[:, 0]
    df['tsne-2d-two'] = tsne_results[:, 1]

    tsne_cluster = df.groupby('cluster').agg({'tsne-2d-one': 'mean', 'tsne-2d-two': 'mean'}).reset_index()

    # 2D PCA 결과를 시각화
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        x="tsne-2d-one", y="tsne-2d-two",
        data=df,
        hue="cluster",
        palette=sns.color_palette("tab10", 5),
        legend="full",
        alpha=1,
        s=50
    )

    plt.scatter(x="tsne-2d-one", y="tsne-2d-two", data=tsne_cluster, s=10, c='b')

    plt.xlabel("PCA 1")
    plt.ylabel("PCA 2")
    plt.title("Anomaly Detection Visualization")
    plt.colorbar(label='Cluster')
    st.pyplot()

# Streamlit 앱
def main():
    st.title('로그 데이터 처리, 이상 탐지 및 시각화 앱')

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

        # 이상 탐지 결과 시각화
        st.write("이상 탐지 결과 시각화:")
        visualize_anomaly(anomaly_df)

        # 처리된 데이터를 새로운 CSV 파일로 저장
        processed_file_path = 'processed_file.csv'
        anomaly_df.to_csv(processed_file_path, index=False)

        # 처리된 파일을 다운로드할 수 있는 링크 제공
        st.markdown(f"처리된 데이터 다운로드: [처리된 파일]({processed_file_path})")

if __name__ == '__main__':
    main()
이 코드를 합하여 streamlit 코드 처음부터 끝까지 생략하지말고 보여줘
