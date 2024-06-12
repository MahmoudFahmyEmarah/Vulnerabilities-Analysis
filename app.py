import streamlit as st
import pandas as pd
import os

from plots import kpi, vulnerabilities_per_platform, closure_status, platforms_close_to_sla_table, \
    most_non_compliant_platforms, statistics, \
    severity_distribution_by_platform
from Emarah import main_Em

def setup_page():
    st.set_page_config(layout="wide")
    st.markdown("""
    <style>
    .title {
        font-size:24px !important;
        font-weight: bold;
        color: #5B006A;
        font-family: Arial;

    }
    .text{
        color:white;
        text-align: center;
        font_family: Arial;
    }
    .statistic{
        color:#600587;
        font-size: 22px;
        font-weight: bold;
        text-align: center;
        font_family: Arial;
    }
    .Card{

        border: 1px solid #ccc; 
        padding: 0px; 
        margin:0px;
        border-radius: 25px; 
        background-color: #EACDFF;
        width: 150px;
        height: 150px;
        text-align: center;

    }
    .Card .top-part {
        background-color: #600587;  /* Change this to the color you want */
        height: 25%;  /* This represents the top 20% of the card */
        width: 100%;
        border-radius: 23px 23px 0 0;  /* Rounded corners at the top */
        padding: 0;  /* Remove padding */
        margin: 0;  /* Remove margin */
    }
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
    st.markdown('<h2 class="title">Vulnerabilities(YTD)</h2>', unsafe_allow_html=True)


@st.cache_data
def process_file(file):
    try:
        df = pd.read_excel(file)
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
def save_processed_file(df, filename):
    try:
        processed_filename = f"processed_{filename}"
        df.to_csv(processed_filename, index=False)
        return processed_filename
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None


def upload_file():
    uploaded_file = st.sidebar.file_uploader("Upload Vulnerabilities Report", type="xlsx")
    return uploaded_file


def apply_filters(df):
    # Add dropdowns to filter based on Applications and SLA Breached (in the sidebar)
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


def create_dashboard(df):
    kpi(df)
    statistics(df)
    vulnerabilities_per_platform(df)
    severity_distribution_by_platform(df)
    col1, col2 = st.columns(2)
    with col1:
        closure_status(df)

    with col2:
        most_non_compliant_platforms(df)
    platforms_close_to_sla_table(df)




# Display the selected page

def main():

    uploaded_file = upload_file()

    if uploaded_file:
        # Check if a processed file already exists
        filename = uploaded_file.name
        processed_filename = f"processed_{filename}"

        if os.path.exists(processed_filename):
            df = pd.read_csv(processed_filename)

        else:
            # Process the file and cache the result
            df = process_file(uploaded_file)

            if df.empty:
                st.stop()  # Stop execution if DataFrame is empty
            # Save the processed DataFrame to a file
            save_processed_file(df, filename)

        # Apply filters
        df = apply_filters(df)
        create_dashboard(df)




if __name__ == "__main__":
    setup_page()

    page = st.sidebar.selectbox('Navigation', ['Page 1', 'Page 2'])
    if page == 'Page 1':
        main()
    elif page == 'Page 2':
        main_Em()
