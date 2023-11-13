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

df_entity = pd.read_csv("train_processed.csv", index_col='entity')
cols_to_train = ['method_cnt','method_post','protocol_1_0','status_major','status_404','status_499','status_cnt','path_same','path_xmlrpc','ua_cnt','has_payload','bytes_avg','bytes_std']

# 모델링
model = load('anomaly_entities_kmeans.pkl')
model2 = load('anomaly_entities_dbscan.pkl') 


# 대시보드 애플리케이션 초기화
dash_app = Dash(__name__, server=app3, url_base_pathname='/dash/')

# Matplotlib 그래프 생성 함수
def generate_pca():
    fig = plt.figure()
    plt.scatter(df_entity['pca_1'], df_entity['pca_2'], c=df_entity['cluster_kmeans'], cmap='viridis', s=60)
    plt.xlabel("PCA 1")
    plt.ylabel("PCA 2")
    # plt.title("Visualization of abnormally detected entities using full features")
    plt.colorbar()
    # plt.colorbar(label='클러스터')

    return fig



# Matplotlib 그래프 생성
pca_fig = generate_pca()

# Matplotlib 그래프를 Plotly 그래프로 변환
canvas = FigureCanvas(pca_fig)
png_output = BytesIO()
canvas.print_png(png_output)



# BytesIO를 base64로 인코딩
data_uri = "data:image/png;base64," + base64.b64encode(png_output.getvalue()).decode()


dash_app.layout = html.Div([
    html.H2(children='Visualization of abnormally detected entities using full features'),
    html.Img(src=data_uri, style={'margin': '0 auto'})
])


if __name__ == '__main__':
    main()
