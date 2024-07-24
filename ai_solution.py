import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder
import os
import json
from st_aggrid import AgGrid, GridOptionsBuilder
import os
from openai import OpenAI
from dotenv import load_dotenv
import json
from pandas import DataFrame
# Function to process the uploaded file
@st.cache_data
def process_file(file, ip_list):
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

        # Filter based on IP list
        df = df[df['Device Name'].isin(ip_list)]

        # Add SLA Remaining Days column
        sla_matrix = {
            'Critical': 7,
            'High': 14,
            'Medium': 30,
            'Low': 45,
            'Minimal': 60
        }
        df['SLA Remaining Days'] = df.apply(lambda x: sla_matrix.get(x['Severity'], 0) - x['Ageing in Days'], axis=1)

        # Identify topics based on keywords
        def identify_topic(row):
            text = f"{row['Title']} {row['Description']} {row['Solution']}".lower()
            if 'redhat' in text or 'ssh' in text:
                return 'OS Issue'
            else:
                return 'Application Issue'

        df['Topic'] = df.apply(identify_topic, axis=1)
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


# Function to check KB for existing solution
def check_kb(application, title):
    filename = f"{application}_KB.csv" if application != 'OS Issue' else "OS_KB.csv"
    if os.path.exists(filename):
        kb_df = pd.read_csv(filename)
        match = kb_df[kb_df['Title'] == title]
        if not match.empty:
            return match.iloc[0]['Recommended Solution']
    return None


# Function to generate a recommendation using OpenAI GPT-3.5 Turbo
def get_recommended_solution(application, title, description, results, operating_system):
    client = OpenAI()
    prompt = (f"You are an experienced System Engineer. Given the following issue details:\n\n"
              f"Related application: {application}\n\n"
              f"Title: {title}\n\n"
              f"Description: {description}\n\n"
              f"Results: {results}\n\n"
              f"Operating System: {operating_system}\n\n"
              "Please recommend a detailed step-by-step solution in technical steps and recommend codes or commands for each step if possible to resolve this issue in JSON format.\n\n"
              "You must return the following key --> Recommended_Solution:")
    print(prompt)
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
    )
    recommendation = response.choices[0].message.content.strip()
    return recommendation


# Function to format the recommendation text
def format_recommendation(json_response):
    print(json_response)
    recommendations = json.loads(json_response)
    step_number = 1
    formatted_recommendation = "Steps:\n"
    for step in recommendations["Recommended_Solution"]:
        for key, value in step.items():
            if isinstance(value, list):
                value = ', '.join(value)
            formatted_recommendation += f"{key}: {value}\n"
        formatted_recommendation += "\n"
        step_number += 1
    return formatted_recommendation.strip()


# Function to save knowledge base entries to CSV files
def save_kb_entry(application, title, description, results, recommended_solution, feedback):
    filename = f"{application}_KB.csv" if application != 'OS Issue' else "OS_KB.csv"
    entry = pd.DataFrame([{
        "Title": title,
        "Description": description,
        "Results": results,
        "Recommended Solution": recommended_solution,
        "Feedback": feedback
    }])
    if os.path.exists(filename):
        kb_df = pd.read_csv(filename)
        kb_df = pd.concat([kb_df, entry], ignore_index=True)
    else:
        kb_df = entry
    kb_df.to_csv(filename, index=False)


def format_os_versions(os_versions_dict):
    formatted_os_versions = "\n".join([f"{key}: {value}" for key, value in os_versions_dict.items()])
    return formatted_os_versions

def ai_solution():
    # Initialize session state for storing the recommended solution and feedback
    if 'recommended_solution' not in st.session_state:
        st.session_state['recommended_solution'] = ""
    if 'feedback' not in st.session_state:
        st.session_state['feedback'] = None

    # Add a Title to the dashboard
    st.markdown('<h1 class="animated-title">Vulnerabilities Management Dashboard</h1>', unsafe_allow_html=True)

    # Upload the vulnerabilities file (in the sidebar)
    uploaded_file = st.sidebar.file_uploader("Upload Vulnerabilities Report", type="xlsx")

    if uploaded_file:
        with st.spinner('Processing file...'):
            # Load the list of IPs from MS_All_servers.xlsx
            ip_file = "MS_All_servers.xlsx"
            if os.path.exists(ip_file):
                ip_df = pd.read_excel(ip_file)
                ip_list = ip_df['IP'].tolist()
            else:
                st.error(f"IP file '{ip_file}' not found.")
                st.stop()  # Stop execution if IP file is not found

            # Check if a processed file already exists
            filename = uploaded_file.name
            processed_filename = f"processed_{filename}"

            if os.path.exists(processed_filename):
                df = pd.read_csv(processed_filename)
            else:
                # Process the file and cache the result
                df = process_file(uploaded_file, ip_list)
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

        topic_options = df['Topic'].unique()
        selected_topic = st.sidebar.selectbox("Filter by Topic", options=["All"] + list(topic_options))

        if selected_topic != "All":
            df = df[df['Topic'] == selected_topic]

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

            title = row_content['Title']
            description = row_content['Description']
            results = row_content['Results']
            operating_system = row_content['Operating System']
            application = row_content['Applications']
            topic = row_content['Topic']

            with st.spinner('Generating recommendation...'):
                recommend_button = st.button("Recommend Solution")
                if recommend_button:
                    # Check the KB for an existing solution
                    kb_solution = check_kb(application, title)
                    if kb_solution:
                        st.session_state['recommended_solution'] = kb_solution
                    else:
                        recommended_solution = get_recommended_solution(application, title, description, results,
                                                                        operating_system)
                        st.session_state['recommended_solution'] = format_recommendation(recommended_solution)
                    st.session_state['feedback'] = None  # Reset feedback when generating a new solution

        if st.session_state.get('recommended_solution'):
            formatted_recommendation = st.session_state['recommended_solution']
            # Use Streamlit's native text_area with increased height to fit the content
            st.text_area("Recommended Solution", formatted_recommendation, height=400, max_chars=None)

            # Like and Dislike buttons
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("👍 Like"):
                    st.session_state['feedback'] = "Like"
            with col2:
                if st.button("👎 Dislike"):
                    st.session_state['feedback'] = "Dislike"

            feedback = st.session_state['feedback']
            st.write(f"Feedback: {feedback}")

            # Save the entry to the knowledge base CSV file
            if feedback:
                save_kb_entry(application, title, description, results, st.session_state['recommended_solution'],
                              feedback)
                st.success(f"Entry saved to {application}_KB.csv")
        # Display statistics about the shown DataFrame
        sla_less_equal_3_days = ((df['SLA Remaining Days'] <= 3) & (df['SLA Remaining Days'] > 0)).sum()
        sla_more_than_3_days = (df['SLA Remaining Days'] > 3).sum()
        st.subheader("Statistics")
        stats = {
            "Total Records": len(df),
            "Unique Applications": df['Applications'].nunique(),
            "Unique Server Nodes": df['Device Name'].nunique(),
            "OS Versions": format_os_versions(df['Operating System'].value_counts().to_dict()),
            # Convert to formatted string
            "Critical Vulnerabilities": (df['Severity'] == 'Critical').sum(),
            "High Vulnerabilities": (df['Severity'] == 'High').sum(),
            "Medium Vulnerabilities": (df['Severity'] == 'Medium').sum(),
            "Low Vulnerabilities": (df['Severity'] == 'Low').sum(),
            "Minimal Vulnerabilities": (df['Severity'] == 'Minimal').sum(),
            "SLA Breached": (df['SLA Breached?'] == 'Non-Compliant').sum(),
            "SLA <= 3 Days": sla_less_equal_3_days,
            "SLA > 3 Days": sla_more_than_3_days
        }

        # Create a DataFrame for statistics
        stats_df = pd.DataFrame(list(stats.items()), columns=['Statistic', 'Value'])

        # Adjust the OS Versions formatting for new lines
        stats_df.loc[stats_df['Statistic'] == 'OS Versions', 'Value'] = stats_df.loc[
            stats_df['Statistic'] == 'OS Versions', 'Value'].apply(lambda x: x.replace("\n", "<br>"))

        # Display the table
        st.markdown(stats_df.to_html(index=False, escape=False, classes="stats-table"), unsafe_allow_html=True)




