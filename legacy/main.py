import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
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

# Function to save feedback and recommendation to a CSV file
def save_feedback_to_csv(data, filename='recommendations.csv'):
    if os.path.exists(filename):
        existing_data = pd.read_csv(filename)
        combined_data = pd.concat([existing_data, data], ignore_index=True)
    else:
        combined_data = data

    combined_data.to_csv(filename, index=False)

# Function to generate a recommendation using OpenAI GPT-3.5 Turbo
def generate_recommendation(title, description, solution):
    
    client = OpenAI()
    prompt = f"Title: {title}\n\nDescription: {description}\n\nSolution: {solution}\n\nRecommend a detailed step-by-step solution to resolve this issue in json format.\n\n Recommended_Solution:"
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
def format_os_versions(os_versions_dict):
    formatted_os_versions = "\n".join([f"{key}: {value}" for key, value in os_versions_dict.items()])
    return formatted_os_versions

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
    selected_sla_breached = st.sidebar.selectbox("Filter by SLA Breached?", options=["All"] + list(sla_breached_options))

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
        width='100%',
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

        # Add a button to recommend a solution
        if st.button('Recommend Solution'):
            title = selected_row['Title']
            description = selected_row['Description']
            solution = selected_row['Solution']

            # Check if the title exists in the CSV file
            csv_filename = 'recommendations.csv'
            if os.path.exists(csv_filename):
                existing_data = pd.read_csv(csv_filename)
                if title in existing_data['Title'].values:
                    st.warning("This issue has already been processed.")
                else:
                    recommendation = generate_recommendation(title, description, solution)
                    st.write("Recommended Solution:")
                    st.write(recommendation)

                    # Add feedback buttons
                    feedback = st.radio("Was this recommendation helpful?", ('Like', 'Dislike'))

                    # Save the feedback and recommendation to the CSV file
                    feedback_data = pd.DataFrame([{
                        'Title': title,
                        'Description': description,
                        'Solution': solution,
                        'Recommendation': recommendation,
                        'Feedback': feedback
                    }])

                    save_feedback_to_csv(feedback_data)
            else:
                recommendation = generate_recommendation(title, description, solution)
                st.write("Recommended Solution:")
                st.write(recommendation)

                # Add feedback buttons
                feedback = st.radio("Was this recommendation helpful?", ('Like', 'Dislike'))

                # Save the feedback and recommendation to the CSV file
                feedback_data = pd.DataFrame([{
                    'Title': title,
                    'Description': description,
                    'Solution': solution,
                    'Recommendation': recommendation,
                    'Feedback': feedback
                }])

                save_feedback_to_csv(feedback_data)

    # Display statistics about the shown DataFrame
    sla_less_equal_3_days = ((df['SLA Remaining Days'] <= 3) & (df['SLA Remaining Days'] > 0)).sum()
    sla_more_than_3_days = (df['SLA Remaining Days'] > 3).sum()
    st.subheader("Statistics")
    stats = {
        "Total Records": len(df),
        "Unique Applications": df['Applications'].nunique(),
        "Unique Server Nodes": df['Device Name'].nunique(),
        "OS Versions": format_os_versions(df['Operating System'].value_counts().to_dict()),  # Convert to formatted string
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
