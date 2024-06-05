import streamlit as st
import pandas as pd
import os
from st_aggrid import AgGrid, GridOptionsBuilder

# CSS code
css_code = '''
<style>
.container {
  padding: 20px;
  width: 100px;
  background-color: #fff5e1;
  border-radius: 10px;
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
}
.kpi{


}


h1 {
  color: #333333;
}
.container1 {
      max-width: 800px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f0f0f0;
      border: 1px solid #ccc;
      border-radius: 5px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
      float:right;

    }

.status {
  margin-top: 20px;
  font-size: 18px;
  font-weight: bold;
}

.upload {
  margin-top: 20px;
}

.button {
  margin-top: 20px;
  padding: 10px 20px;
  background-color: #4caf50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.button:hover {
  background-color: #45a049;
}

.warning {
  color: red;
  font-weight: bold;
  margin-top: 20px;
}
.container2 {
    position: absolute;
    right: -100px;
    color: red;
}
.title{
color:white;
}
</style>
'''
# HTML code
html_code = f'''
{css_code}


'''

st.set_page_config(layout="wide")

st.subheader("Vulnerabilities(YTD)")


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
        if df.empty:
            st.stop()  # Stop execution if DataFrame is empty
        # Save the processed DataFrame to a file
        save_processed_file(df, filename)

    # Add dropdowns to filter based on Applications and SLA Breached (in the sidebar)
    col1, col2, col3, col4, col5 = st.columns(5)

    # this col talk about KPI with servity , LOW , Medium , High ,Critical etc

    with col1:
        total = len(df)
        st.markdown(f"""
             <div style='border: 1px solid #ccc; padding: 10px; border-radius: 25px; background-color: #600587;'>
              <h3 style="color: white; text-align: center;">Total</h3>
               <h4 style="color: white;text-align:center;" >{total}</h4>



       </div>

           """, unsafe_allow_html=True)
    with col2:
        critical = (df['Severity'] == 'Critical').sum()
        st.markdown(f"""
             <div style='border: 1px solid #ccc; padding: 10px; border-radius: 25px; background-color: #600587;'>
              <h3 style="color: white; text-align: center;">Critical</h3>
               <h4 style="color: white;text-align:center;" >{critical}</h4>


       </div>

           """, unsafe_allow_html=True)

    with col3:
        high = (df['Severity'] == 'High').sum()
        st.markdown(f"""
             <div style='border: 1px solid #ccc; padding: 10px; border-radius: 25px; background-color: #600587;'>
              <h3 style="color: white; text-align: center;">High</h3>
               <h4 style="color: white;text-align:center;" >{high}</h4>



       </div>

           """, unsafe_allow_html=True)
    with col4:
        medium = (df['Severity'] == 'Medium').sum()
        st.markdown(f"""
             <div style='border: 1px solid #ccc; padding: 10px; border-radius: 25px; background-color: #600587;'>
              <h3 style="color: white; text-align: center;">Medium</h3>
               <h4 style="color: white;text-align:center;" >{medium}</h4>



       </div>

           """, unsafe_allow_html=True)
    with col5:
        Low = (df['Severity'] == 'Low').sum()
        st.markdown(f"""
             <div style='border: 1px solid #ccc; padding: 10px; border-radius: 25px; background-color: #600587;'>
              <h3 style="color: white; text-align: center;">Low</h3>
               <h4 style="color: white;text-align:center;" >{Low}</h4>



       </div>

           """, unsafe_allow_html=True)

    st.markdown(html_code, unsafe_allow_html=True)
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








