import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder
import os
import plotly.express as px

import streamlit.components.v1 as components

# Define the iframe code
iframe_code = """
<iframe title="FINAL_touches" width="1140" height="541.25" src="https://app.powerbi.com/reportEmbed?reportId=1683b4a1-7656-4b47-b888-07c40d42b3b5&autoAuth=true&ctid=aadc0e0a-65ee-471a-99a1-9f86faecbaed" frameborder="0" allowFullScreen="true"></iframe>"""
# Function to process the uploaded file
@st.cache_data
def process_file(file):
    try:
        df = pd.read_excel(file)
        df = df[df['Overall Status'] == 'Open']

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
        df['SLA Remaining Days'] = df.apply(lambda x: sla_matrix.get(x['Severity'], 0) - x['Ageing in Days'], axis=1)

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


# Upload the vulnerabilities file (in the sidebar)
uploaded_file = st.sidebar.file_uploader("Upload Vulnerabilities Report", type="xlsx")

if uploaded_file:
    # Check if a processed file already exists
    filename = uploaded_file.name
    processed_filename = f"processed_{filename}"

    if os.path.exists(processed_filename):
        df = pd.read_csv(processed_filename)
    else:
        # Process the file and cache the result
        df = process_file(uploaded_file)
        total_vulnerabilities = len(df)
        if df.empty:
            st.stop()  # Stop execution if DataFrame is empty
        # Save the processed DataFrame to a file
        save_processed_file(df, filename)

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

    # Display the filtered DataFrame using AgGrid for interactivity
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_selection(selection_mode="single", use_checkbox=False)

    # Set the column widths and ensure they are wide enough to display the content
    columns = df.columns
    for column in columns:
        gb.configure_column(column, width=200)  # Adjust the width as needed

    grid_options = gb.build()

    grid_response = AgGrid(
        df,
        gridOptions=grid_options,
        height=400,
        width='150%',
        data_return_mode='AS_INPUT',
        update_mode='MODEL_CHANGED',
        fit_columns_on_grid_load=False,  # Ensure columns are not auto-fitted
        allow_unsafe_jscode=True,  # This enables the usage of JsCode
        enable_enterprise_modules=False,
    )

    # Get the selected row
    selected_rows = grid_response.get('selected_rows', pd.DataFrame())
    if isinstance(selected_rows, pd.DataFrame) and not selected_rows.empty:
        selected_row = selected_rows.iloc[0]
        row_content = selected_row.to_dict()
        st.json(row_content)

    # Display statistics about the shown DataFrame
    sla_less_equal_3_days = ((df['SLA Remaining Days'] <= 3) & (df['SLA Remaining Days'] > 0)).sum()
    sla_more_than_3_days = (df['SLA Remaining Days'] > 3).sum()
    st.subheader("Statistics")
    stats = {
        "Total Records": len(df),
        "Unique Applications": df['Applications'].nunique(),
        "Critical Vulnerabilities": (df['Severity'] == 'Critical').sum(),
        "High Vulnerabilities": (df['Severity'] == 'High').sum(),
        "Medium Vulnerabilities": (df['Severity'] == 'Medium').sum(),
        "Low Vulnerabilities": (df['Severity'] == 'Low').sum(),
        "Minimal Vulnerabilities": (df['Severity'] == 'Minimal').sum(),
        "SLA Breached": (df['SLA Breached?'] == 'Non-Compliant').sum(),
        "SLA <= 3 Days": sla_less_equal_3_days,
        "SLA > 3 Days": sla_more_than_3_days
    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Statistic', 'Value'])
    st.table(stats_df.style.hide(axis='index'))

    # Create a dashboard for visualization
    st.subheader("Dashboard")
    # Button to go to the Dash dashboard
    st.markdown("""
    <a href="http://localhost:8050" target="_blank">
        <button style='margin: 10px 0px; padding: 10px 20px; background-color: #4CAF50; color: white; border: none; cursor: pointer;'>
            Go to Dashboard
        </button>
    </a>
    """, unsafe_allow_html=True)

    components.html(iframe_code, height=800 ,width=1200)
    # Add CSS for the grid layout
    st.markdown('''
        <style>
        .card-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(60px, 1fr));
            gap: 10px;
        }
        .card {
            box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2);
            transition: 0.3s;
            border-radius: 5px;
            padding: 20px;
            text-align: center;
        }
        </style>
    ''', unsafe_allow_html=True)

    # Start the card container
    st.markdown('<div class="card-container">', unsafe_allow_html=True)

    # Iterate over the DataFrame and create a card for each statistic
    for i, row in stats_df.iterrows():
        st.markdown(f'''
        <div class="card">
            <h3>{row["Statistic"]}</h3>
            <p>{row["Value"]}</p>
        </div>
        ''', unsafe_allow_html=True)

    # Close the card container
    st.markdown('</div>', unsafe_allow_html=True)