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

# Entity 정의
pat = re.compile(r"(\d+)[.](\d+)[.](\d+)[.](\d+)")
df_train = df_orig[df_orig['Host'].str.match(pat)==True]
df_entity = pd.DataFrame({"entity":list(df_train['Host'].unique())})
df_entity = df_entity.set_index('entity')

# Feature Engineering 함수 정의
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
        if cnt % 500 == 0:
            print(cnt)

        group = df_train[df_train['Host']==entity]

        method_cnt = group['Method'].nunique()
        df.loc[entity, 'method_cnt'] = method_cnt

        method_post_percent = len(group[group['Method']=='POST']) / float(len(group))
        df.loc[entity, 'method_post'] = method_post_percent

        use_1_0 = True if len(group[group['Protocol']=='HTTP/1.0']) > 0 else False
        df.loc[entity, 'protocol_1_0'] = use_1_0

        status_major_percent = len(group[group['Status'].isin(['200', '301', '302'])]) / float(len(group))
        df.loc[entity, 'status_major'] = status_major_percent

        status_404_percent = len(group[group['Status'].isin(['404'])]) / float(len(group))
        df.loc[entity, 'status_404'] = status_404_percent

        has_499 = True if len(group[group['Status']=='499']) > 0 else False
        df.loc[entity, 'status_499'] = has_499

        status_cnt = group['Status'].nunique()
        df.loc[entity, 'status_cnt'] = status_cnt

        top1_path_cnt = group['Path'].value_counts()[0]
        df.loc[entity, 'path_same'] = float(top1_path_cnt / len(group))

        path_xmlrpc = len(group[group['Path'].str.contains('xmlrpc.php')==True]) / float(len(group))
        df.loc[entity, 'path_xmlrpc'] = path_xmlrpc

        df.loc[entity, 'ua_cnt'] = group['UA'].nunique()

        has_payload = []
        if len(group[group['Payload'] != '-']) > 0:
            has_payload.append(True)
        else:
            has_payload.append(False)
        df.loc[entity, 'has_payload'] = has_payload

        df.loc[entity, 'bytes_avg'] = np.mean(group['Bytes'])
        df.loc[entity, 'bytes_std'] = np.std(group['Bytes'])

        cnt = cnt + 1
    return df

# Feature 추출한 결과를 스토리지에 저장
df_entity = feature_extract(df_entity)
df_entity.to_csv(colab_path + "/data_with_feature_csv/train_processed.csv")

# 저장한 데이터 파일 로드
df_entity = pd.read_csv(colab_path + "/data_with_feature_csv/train_processed.csv", index_col='entity')

# 결측치 처리
df_entity.fillna(0, inplace=True)

# 이상값 처리 - BoxPlot
plt.figure(figsize=(15,15))
cols = ['method_cnt','method_post','status_major','status_404','status_cnt','path_same','ua_cnt','bytes_avg','bytes_std']
for i in range(len(cols)):
    plt.subplot(3, 3, i+1)
    plt.boxplot([df_entity[cols[i]]])
    plt.xticks([1],[cols[i]])

# 데이터 정규화
columns_to_scale = ['method_cnt', 'status_cnt', 'ua_cnt', 'bytes_avg', 'bytes_std']
scaler = preprocessing.MinMaxScaler()
scaler = scaler.fit(df_entity[columns_to_scale])
df_entity[columns_to_scale] = scaler.transform(df_entity[columns_to_scale])

# 2D, 3D 산포도 분석
df_entity.plot.scatter(x='method_post', y='status_404', alpha=0.5)
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')
ax.scatter(df_entity['method_post'], df_entity['status_404'], df_entity['ua_cnt'])
ax.set_xlabel('method_post')
ax.set_ylabel('status_404')
ax.set_zlabel('ua_cnt')

# 모델링 - K-means
cols_to_train = ['method_cnt','method_post','protocol_1_0','status_major','status_404','status_499','status_cnt','path_same','path_xmlrpc','ua_cnt','has_payload','bytes_avg','bytes_std']
model_kmeans = KMeans(n_clusters=2, random_state=42)
model_kmeans.fit(df_entity[cols_to_train])

# Predict를 통해 클러스터 할당
df_entity['cluster_kmeans'] = model_kmeans.predict(df_entity[cols_to_train])

# Outlier 클러스터에 속한 데이터 포인트 수 확인
df_entity['cluster_kmeans'].value_counts()

# 모델을 파일로 저장
with open(colab_path + "/anomaly_entities_kmeans.pkl", 'wb') as f:
    pickle.dump(model_kmeans, f)

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
