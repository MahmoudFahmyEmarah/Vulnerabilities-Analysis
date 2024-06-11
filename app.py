import streamlit as st
import pandas as pd
import os
from st_aggrid import AgGrid, GridOptionsBuilder
import plotly.express as px
import matplotlib.pyplot as plt
from datetime import datetime
import plotly.graph_objects as go


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
st.markdown("""
<style>
.title {
    font-size:24px !important;
    font-weight: bold;
    color: #5B006A;
}
.text{
    color:white;
    text-align: center;


}
.Card{

    border: 1px solid #ccc; 
    padding: 10px; 
    margin:5px;
    border-radius: 25px; 
    background-color: #600587;
    width: 150px;
    height: 150px;

}
.Card2{
    display:flex;
    justify-content: space-between;
    align-items: center;
    border: 1px solid #ccc; 
    padding: 10px; 
    border-radius: 25px; 
    background-color: #FF375E;

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
.Top {
 background-color: #5B006A;
 color: white;
}
</style>
""", unsafe_allow_html=True)
st.markdown('<h2 class="title">Vulnerabilities(YTD)</h2>', unsafe_allow_html=True)

#KPI Fun to measurements Servity
def KPI():
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

    # this col talk about KPI with servity , LOW , Medium , High ,Critical etc

    with col1:
        total = len(df)
        st.markdown(f"""
                     <div class ="Card">
                      <h3 class ="text">Total</h3>
                       <h4 class ="text">{total}</h4>
                       <h5 class ="text">164 Servers</h4>



               </div>

                   """, unsafe_allow_html=True)
    with col2:
        critical = (df['Severity'] == 'Critical').sum()
        st.markdown(f"""
                     <div class ="Card">
                            <h3 class ="text">Critical</h3>
                            <h4 class ="text" >{critical}</h4>



               </div>

                   """, unsafe_allow_html=True)

    with col3:
        high = (df['Severity'] == 'High').sum()
        st.markdown(f"""
                     <div class ="Card">
                      <h3 class ="text">High</h3>
                       <h4 class ="text" >{high}</h4>



               </div>

                   """, unsafe_allow_html=True)
    with col4:
        medium = (df['Severity'] == 'Medium').sum()
        st.markdown(f"""
                     <div class ="Card">
                      <h3 class ="text">Medium</h3>
                       <h4 class ="text" >{medium}</h4>
                       <h5 class ="text">20 Servers</h4>



               </div>

                   """, unsafe_allow_html=True)
    with col5:
        Low = (df['Severity'] == 'Low').sum()
        st.markdown(f"""
                     <div class ="Card">
                      <h3 class ="text">Low</h3>
                       <h4 class ="text">{Low}</h4>
                        <h5 class ="text">132 Servers</h4>




               </div>

                   """, unsafe_allow_html=True)
    # with col6:
    #     high = (df['Severity'] == 'High').sum()
    #     critical = (df['Severity'] == 'Critical').sum()
    #     st.markdown(f"""
    #         <div class="Card2">
    #             <div class="main-box">
    #                 <div class="priority-box high">
    #                     <span class="text">{critical}</span>
    #                     <div class ="Top"> High
    #                     </div>
    #                 </div>
    #                 <div class="priority-box critical">
    #                     <span class="text">{high}</span>
    #                     <div class ="Top"> Critical
    #                     </div>
    #                 </div>
    #             </div>
    #         </div>
    #
    #
    #         """, unsafe_allow_html=True)



    with col6:
        #sub last data and first data to

        df['Days'] = (pd.to_datetime(df['Date Last Found']) - pd.to_datetime(df['Date First Found'])).dt.days
        df['WithSLA'] = 0

        # Define conditions and update 'WithSLA'
        #check for the days and make sure if it close to SLA or not , above 60 Days it not compliant .
        df.loc[((df["Days"].between(4, 7)) & (df["Severity"] == "Critical")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(10, 14)) & (df["Severity"] == "High")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(20, 30)) & (df["Severity"] == "Medium")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(40, 45)) & (df["Severity"] == "Low")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(55, 60)) & (df["Severity"] == "Minimal")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(0, 100)) & (df["SLA Breached?"] == "Non-Compliant")), 'WithSLA'] = 2

        df.loc[df['WithSLA'] == 0, 'WithSLA'] = "Closed"
        df.loc[df['WithSLA'] == 1, 'WithSLA'] = "WithSLA"
        df.loc[df['WithSLA'] == 2, 'WithSLA'] = "Non-Compliant"



        st.markdown(f"""
                  <div class ="Card">
                      <h3 class ="text">Close to SLA</h3>
                      <h4 class ="text" >{ (df['WithSLA'] == 'WithSLA').sum() }</h4>
                  </div>

                    """, unsafe_allow_html=True)

    with col7:
        st.markdown(f"""
                            <div class ="Card">
                                <h4 class ="text">Branched SLA</h3>
                                <h5 class ="text" >{(df['WithSLA'] == 'Non-Compliant').sum()}</h4>
                            </div>

                              """, unsafe_allow_html=True)




def Vulnerabilities_chart(df):
    keywords = df['Applications'].unique().tolist()
    df_closed = df[(df['Overall Status'] == 'Closed')]
    df_open = df[(df['Overall Status'] == 'Open')]
    df_not = df[(df['WithSLA'] == 'Non-Compliant') ]

    fig = go.Figure()

    fig.add_trace(
        go.Bar(x=keywords, y=df_closed.groupby('Applications').size().reindex(keywords, fill_value=0), name='Closed', width=0.1))
    fig.add_trace(go.Bar(x=keywords, y=df_open.groupby('Applications').size().reindex(keywords, fill_value=0), name='Open', width=0.1))
    fig.add_trace(
        go.Bar(x=keywords, y=df_not.groupby('Applications').size().reindex(keywords, fill_value=0), name='Non-Compliant', width=0.1))

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Vulnerabilities per platform</span>",
        xaxis_title='Platform',
        yaxis_title='Values',
    )

    # Display the chart using Streamlit
    st.plotly_chart(fig)






#Cluster Chart with any vulnerablities close to SLA
def Cluster_status(df):
    #Cluster Chart with any vulnerablities close to SLA
    sla_counts = df['WithSLA'].value_counts()
    fig = px.pie(names=sla_counts.index, values=sla_counts.values, labels=sla_counts.index,
                 title="<span style='color:#600587; font-size:20px'>Cluster Status </span>", hole=0.3)
    # Show the chart
    st.plotly_chart(fig)

def Platforms_chart(df):
    st.markdown('<h2 class="title">PlatForm Close to SLA</h2>', unsafe_allow_html=True)


    specific_columns = df[['Applications', 'Title', 'WithSLA', 'Severity',"Days","SLA Remaining Days"]]

    # Filter 'WithSLA' column to only include rows where the value is 'withSLA'
    specific_columns = specific_columns[specific_columns['WithSLA'] == 'WithSLA']
    st.table(specific_columns.reset_index(drop=True))


def Platform_chart_NonCompliant(df):

    # Filter the   rows with 'WithSLA' containing 'Non-Compliant'
    filtered_df = df[df['WithSLA'] == 'Non-Compliant']
    counts = filtered_df['Applications'].value_counts()

    fig = px.bar(x=counts.index, y=counts.values, labels={'x': 'Applications', 'y': 'Count'},
                 title="<span style='color:#600587; font-size:20px'>Most Non-Compliant Platform</span>")

    # Show the chart
    st.plotly_chart(fig)


def statistics(df):

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
        "SLA > 3 Days": sla_more_than_3_days,

    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Statistic', 'Value'])
    st.table(stats_df.style.hide(axis='index'))


def Stacked_chart(df):
    keywords = df['Applications'].unique().tolist()
    df_low = df[(df['Severity'] == 'Low')]
    df_med = df[(df['Severity'] == 'Medium')]
    df_high = df[(df['Severity'] == 'High')]
    df_Critical = df[(df['Severity'] == 'Critical')]
    df_medin= df[(df['Severity'] == 'Minimal')]


    fig = go.Figure()

    fig.add_trace(
        go.Bar(x=keywords,
               y=df_low.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Low',
               marker_color='blue',
               width=0.1, ))
    fig.add_trace(
        go.Bar(x=keywords,
               y=df_med.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Medium',
               marker_color='orange',
               width=0.1))
    fig.add_trace(
        go.Bar(x=keywords,
               y=df_high.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='High',
               marker_color='red',
               width=0.1))

    fig.add_trace(
        go.Bar(x=keywords,
               y=df_medin.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Minimal',
               marker_color='lightgreen',
               width=0.1))


    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Severity Distribution by Platform</span>",
        xaxis_title='Platform',
        yaxis_title='Values',
    )
    # Display the chart using Streamlit
    st.plotly_chart(fig)
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

    # call fun
    # Create a dashboard for visualization



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
    #Fun call
    KPI()
    statistics(df)
    Vulnerabilities_chart(df)
    Stacked_chart(df)

    col3,col4 = st.columns(2)
    with col3:
        Cluster_status(df)

    with col4:
        Platform_chart_NonCompliant(df)


    Platforms_chart(df)

    # Sample data

































