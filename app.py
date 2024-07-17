import base64

import streamlit as st
import pandas as pd
import os

from matplotlib import pyplot as plt
from pandas import DataFrame
from pygments.lexers import go

from plots import kpi, vulnerabilities_per_platform, closure_status, \
    most_non_compliant_platforms, statistics, compare_data,display_kpi,\
    severity_distribution_by_platform, vulnerabilities_per_month, vulnerabilities_by_server,app_os
from ai_solution import ai_solution
from plotly import graph_objects as go
import plotly.express as px

def setup_page():
    """
    Setup the page layout and styling
    :return:
    """
    st.set_page_config(layout="wide")
    st.markdown("""
    <style>
        .page-title {
        font-size:24px !important;
        font-weight: bold;
        color: #FFFFFF;
        font-family: Arial;
    }
    .plot-title {
        font-size:20px !important;
        font-weight: bold;
        color: #FFFFFF;
        font-family: Arial;
    }
    .title {
        font-size:20px !important;
        font-weight: bold;
        color: #FFFFFF;
        font-family: Arial;
        position: absolute;
        top: 0;
        left: 50%;
        transform: translate(-50%, 0);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .number{
        font-size:20px !important;
        font-weight: bold;
        color: #5B006A;
        font-family: Arial;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
    }
    .subtitle{
        font-size:18px !important;
        font-weight: normal;
        color: #5B006A;
        font-family: Arial;
        position: absolute;
        bottom: 0;
        left: 50%;
        transform: translate(-50%, 0);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .Card{
        border: 2px solid #ccc;
        padding: 15px;
        margin:0px;
        border-radius: 30px;
        background: linear-gradient(to right, #EACDFF, #fff);
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        width: 170px;
        height: 150px;
        text-align: center;
        display: flex;
        justify-content: center;
        align-items: center;
        position: relative;
        flex-direction: column;

    }
    .Card .top-part {
        background-color: #600587;  /* Change this to the color you want */
        height: 25%;  /* This represents the top 20% of the card */
        width: 100%;
        border-radius: 28px 28px 0 0;  /* Rounded corners at the top */
        position: absolute;
        top: 0;
        left: 0;
    }
    .high-priority {
            background-color: red;
            width: 315px;
            height: 199px;
            border: 2px solid #ccc;
            padding: 3px;
            border-radius: 30px;
            text-align: center;
            display: flex;
            justify-content: space-between;
        }
    .high-priority-text {
            position: absolute;
            bottom: -7px;
            left: 30%;
            transform: translateX(50%);
            font-size: 22px;
            color: white;
            font-weight: bold;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
    .main-box {
        display: flex;
      justify-content: space-around;
      align-items: flex-end;
      border-radius: 10px;
      padding: 20px;
    }
    .priority-box {
      margin: 5px;
      border-radius: 5px;

    }
    .priority-box.high,
    .priority-box.critical {
      background-color: #EACDFF;
      text-align: center;
    }
    </style>
    """, unsafe_allow_html=True)
    st.markdown('<h2 class="page-title">Vulnerabilities(YTD)</h2>', unsafe_allow_html=True)


@st.cache_data

# Function to process the file from a given file path
def process_file(file_path: str) -> DataFrame:
    """
    Process the file from the specified path and return the processed DataFrame
    :param file_path: Path to the Excel file
    :return: df
    """
    try:
        df = pd.read_excel(file_path)
        columns_to_remove = [
            'General Department Name', 'Department', 'Application Delegate', 'Section Manager',
            'Last Scan Date Time', 'Last Vulnerability Authenticated Scanned Date Time',
            'VM Integration', 'VM Authentication', 'Authentication Summary', 'Scan Result ID',
            'Qualys ID', 'Port Number', 'Vulnerability Reference(s)', 'Related CVEs'
        ]
        df = df.drop(columns=columns_to_remove)

        # Add SLA Remaining Days column
        sla_matrix = {
            'Critical': 7,
            'High': 14,
            'Medium': 30,
            'Low': 45,
            'Minimal': 60
        }

        df['SLA Remaining Days'] = df.apply(lambda x: abs(sla_matrix.get(x['Severity'], 0) - x['Ageing in Days']),
                                            axis=1)

        # Filter out rows that do not contain specific keywords in the Applications column
        keywords = ["Nifi", "CDP", "Airflow", "R-Studio", "Git"]
        df = df[df['Applications'].str.contains('|'.join(keywords), na=False)]
        return df
    except Exception as e:
        st.error(f"Error processing file: {e}")
        return pd.DataFrame()  # Return an empty DataFrame on error


# Function to save the processed DataFrame
# Function to save the processed DataFrame
def save_processed_file(df: DataFrame, filename: str) -> None:
    try:
        processed_filename = f"processed_{filename}"
        df.to_csv(processed_filename, index=False)
        st.info(f"Processed file saved as {processed_filename}")
    except Exception as e:
        st.error(f"Error saving file: {e}")

# Main function to process the file and display the results




# def upload_file():
#     """
#     Upload the vulnerabilities file (in the sidebar)
#     :return: uploaded_file
#     """
#     uploaded_file = st.sidebar.file_uploader("Upload Vulnerabilities Report", type="xlsx")
#
#     return uploaded_file


def apply_filters(df: DataFrame):
    """
    Apply filters to the DataFrame based on the selected options
    :param df: type: DataFrame
    :return:df type: DataFrame
    """
    st.sidebar.header("Filters")
    applications = df['Applications'].unique()
    selected_application = st.sidebar.selectbox("Filter by Application", options=["All"] + list(applications))

    if selected_application != "All":
        df = df[df['Applications'] == selected_application]

    sla_breached_options = df['SLA Breached?'].unique()
    selected_sla_breached = st.sidebar.selectbox("Filter by SLA Breached?",
                                                 options=["All"] + list(sla_breached_options))

    if selected_sla_breached != "All":
        df = df[df['SLA Breached?'] == selected_sla_breached]

    severity_options = df['Severity'].unique()
    selected_severity = st.sidebar.selectbox("Filter by Severity", options=["All"] + list(severity_options))

    if selected_severity != "All":
        df = df[df['Severity'] == selected_severity]

    return df


def create_dashboard(df: DataFrame):
    """
    Create the dashboard with the given DataFrame
    :param df:
    :return:
    """
    kpi(df)
    statistics(df)
    vulnerabilities_per_month(df)
    vulnerabilities_per_platform(df)
    severity_distribution_by_platform(df)
    col1, col2 = st.columns(2)
    with col1:
        closure_status(df)
        app_os(df)
    with col2:
        vulnerabilities_by_server(df)
        most_non_compliant_platforms(df)





def dashboard_service(file_path: str):
    """
    Main function to run the dashboard service with a specified file path

    :param file_path: Path to the Excel file
    """
    try:
        # Check if a processed file already exists
        filename = os.path.basename(file_path)
        processed_filename = f"processed_{filename}"

        if os.path.exists(processed_filename):
            df = pd.read_csv(processed_filename)
        else:
            # Process the file and cache the result
            df = process_file(file_path)

            if df.empty:
                st.error("Processed DataFrame is empty.")
                return

            # Save the processed DataFrame to a file
            save_processed_file(df, filename)

        # Apply filters if needed
        df = apply_filters(df)

        # Create and display the dashboard
        create_dashboard(df)

    except Exception as e:
        st.error(f"Error: {e}")










if __name__ == "__main__":
    setup_page()

    st.sidebar.image("STC.png", width=200)

    main_bg = """
            <style>
            [data-testid="stAppViewContainer"]{
                background-color: #7233A3;
            }
           
            [data-testid="stHeader"] {
             z-index: 0;
}
            [data-testid="stToolbar"]{
                display: none;
            }
            </style>
            """
    st.markdown(main_bg, unsafe_allow_html=True)
    page = st.sidebar.selectbox('Navigation', ['Week1', 'Week2',"Compare"])
    if page == 'Week1':
        file_path = "C:/Users/fahda/Downloads/new.xlsx"
        dashboard_service(file_path)

    elif page == 'Week2':
        file_path = "C:/Users/fahda/Downloads/Detailed_Vulnerabilities_Report.xlsx"
        dashboard_service(file_path)

    elif page =="Compare":
        file_path_week1 = "C:/Users/fahda/Downloads/new.xlsx"
        file_path_week2 = "C:/Users/fahda/Downloads/Detailed_Vulnerabilities_Report.xlsx"

        data_week1 = process_file(file_path_week1)
        data_week2 = process_file(file_path_week2)

        compare_data(data_week1, data_week2)



