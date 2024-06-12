import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder
import os


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


def main_Em():
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

        # Example visualizations (you can customize these as needed)
        bar_width = 50  # Set a consistent bar width

        application_chart = alt.Chart(df).mark_bar(size=bar_width).encode(
            x=alt.X('Applications', axis=alt.Axis(labelAngle=-45)),
            y='count()',
            tooltip=['Applications', 'count()']
        ).properties(width=600)

        sla_breached_chart = alt.Chart(df).mark_bar(size=bar_width).encode(
            x='SLA Breached?',
            y='count()',
            tooltip=['SLA Breached?', 'count()']
        ).properties(width=600)

        severity_chart = alt.Chart(df).mark_bar(size=bar_width).encode(
            x='Severity',
            y='count()',
            tooltip=['Severity', 'count()']
        ).properties(width=600)

        st.altair_chart(application_chart, use_container_width=True)
        st.altair_chart(sla_breached_chart, use_container_width=True)
        st.altair_chart(severity_chart, use_container_width=True)
        st.bar_chart(df['SLA Remaining Days'])
        # Add a graph for SLA remaining days
        st.subheader("SLA Remaining Days Distribution")
        sla_data = {
            'SLA Remaining Days': ['<= 3 Days', '> 3 Days'],
            'Count': [sla_less_equal_3_days, sla_more_than_3_days]
        }
        sla_df = pd.DataFrame(sla_data)
        sla_chart = alt.Chart(sla_df).mark_bar(size=bar_width).encode(
            x='SLA Remaining Days',
            y='Count',
            tooltip=['SLA Remaining Days', 'Count']
        ).properties(width=600)

        st.altair_chart(sla_chart, use_container_width=True)

