import streamlit as st
import pandas as pd
from st_aggrid import AgGrid, GridOptionsBuilder
import os

# Function to process the uploaded file
@st.cache_data
def process_file(file):
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
    
    return df

# Function to save the processed DataFrame
def save_processed_file(df, filename):
    processed_filename = f"processed_{filename}"
    df.to_csv(processed_filename, index=False)
    return processed_filename

# Step 1: Upload the vulnerabilities file (in the sidebar)
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
        # Save the processed DataFrame to a file
        save_processed_file(df, filename)

    # Step 5: Add dropdowns to filter based on Applications and SLA Breached (in the sidebar)
    st.sidebar.header("Filters")

    applications = df['Applications'].unique()
    selected_application = st.sidebar.selectbox("Filter by Application", options=["All"] + list(applications))

    if selected_application != "All":
        df = df[df['Applications'] == selected_application]

    sla_breached_options = df['SLA Breached?'].unique()
    selected_sla_breached = st.sidebar.selectbox("Filter by SLA Breached?", options=["All"] + list(sla_breached_options))

    if selected_sla_breached != "All":
        df = df[df['SLA Breached?'] == selected_sla_breached]

    severity_options = df['Severity'].unique()
    selected_severity = st.sidebar.selectbox("Filter by Severity", options=["All"] + list(severity_options))

    if selected_severity != "All":
        df = df[df['Severity'] == selected_severity]

    # Step 7: Display the filtered DataFrame using AgGrid for interactivity
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_selection(selection_mode="single", use_checkbox=True)

    # Set the column widths and ensure they are wide enough to display the content
    columns = df.columns
    for column in columns:
        gb.configure_column(column, width=300)  # Adjust the width as needed

    grid_options = gb.build()

    grid_response = AgGrid(
        df,
        gridOptions=grid_options,
        height=400,
        width='100%',
        data_return_mode='AS_INPUT',
        update_mode='MODEL_CHANGED',
        fit_columns_on_grid_load=False,  # Ensure columns are not auto-fitted
        allow_unsafe_jscode=True,  # This enables the usage of JsCode
        enable_enterprise_modules=False,
    )

    # Get the selected row
    selected_rows = grid_response.get('selected_rows', [])
    if isinstance(selected_rows, list) and len(selected_rows) > 0:
        selected_row = selected_rows[0]
        row_content = pd.DataFrame([selected_row]).to_dict(orient='records')[0]
        st.text_area("Row content", value=str(row_content), height=200)

    # Step 9: Create a dashboard for visualization
    st.subheader("Dashboard")

    # Example visualizations (you can customize these as needed)
    st.bar_chart(df['Applications'].value_counts())
    st.bar_chart(df['SLA Breached?'].value_counts())
    st.bar_chart(df['Severity'].value_counts())
    st.bar_chart(df['SLA Remaining Days'])
