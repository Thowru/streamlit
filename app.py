# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn import preprocessing
import pickle
from sklearn.decomposition import PCA
import seaborn as sns
import matplotlib.pyplot as plt

# 스트림릿 제목 설정
st.title("Access Log Anomaly Detection")

# 로그 파일 업로드
uploaded_file = st.file_uploader("Upload your access log file", type=["csv", "log"])

if uploaded_file is not None:
    # 업로드된 파일을 데이터프레임으로 읽기
    df = pd.read_csv(uploaded_file)

    # Feature Engineering 및 전처리 (예: 사용할 feature를 선택하고, 필요한 전처리 수행)
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

    # 이상 탐지 결과 표시
    st.write("Anomaly Detection Result:")
    if df['cluster'].iloc[0] == 0:
        st.warning("This log file is detected as an anomaly.")
    else:
        st.success("This log file is normal.")

    # 이상 탐지된 클러스터 시각화
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

    # 선택된 엔터티의 로그 데이터 표시
    st.write("Sample Logs:")
    st.dataframe(df.head())
