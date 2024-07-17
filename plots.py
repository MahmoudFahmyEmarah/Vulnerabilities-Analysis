import pandas as pd
import streamlit as st
from pandas import DataFrame
from plotly import graph_objects as go
import plotly.express as px
import numpy as np



#TODO we need to move any preprocessing on the df to the preprocessing.py file to save the preprocessed file and load it here
def kpi(df: DataFrame):
    """
    Display the KPIs for the given DataFrame
    :param df:
    :return:
    """
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

    with col1:
        total = len(df)

        st.markdown(f"""
            <div class ="Card">
                <div class="top-part">
                    <div class="title">Total</div>
                </div>
                <div class="number">{total}</div>
                <div class="subtitle">164 Servers</div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="high-priority" style="background-color: red;">
                <div class="Card">
                    <div class="top-part"></div>
                    <div class="title">Critical</div>
                    <div class="number">{(df['Severity'] == 'Critical').sum()}</div>
                </div>
                <div class="Card">
                    <div class="top-part"></div>
                    <div class="title">High</div>
                    <div class="number">{(df['Severity'] == 'High').sum()}</div>
                </div>
            </div>
            <div class="high-priority-text">High Priority</div>
        """, unsafe_allow_html=True)
    with col4:
        medium = (df['Severity'] == 'Medium').sum()
        st.markdown(f"""
                     <div class ="Card">
                     <div class="top-part">
                      <div class ="title">Medium</div>
                      </div>
                       <div class ="number" >{medium}</div>
                       <div class ="subtitle">20 Servers</div>
               </div>

                   """, unsafe_allow_html=True)
    with col5:
        low = (df['Severity'] == 'Low').sum()
        st.markdown(f"""
                     <div class ="Card">
                        <div class="top-part">
                      <div class ="title">Low</div>
                        </div>
                       <div class ="number">{low}</div>
                        <div class ="subtitle">132 Servers</div>
               </div>

                   """, unsafe_allow_html=True)
    with col6:
        df['Days'] = (pd.to_datetime(df['Date Last Found']) - pd.to_datetime(df['Date First Found'])).dt.days
        df['WithSLA'] = 0
        #Todo There is a column called 'Days' already in the datframe

        # Define conditions and update 'WithSLA'
        #check for the days and make sure if it close to SLA or not , above 60 Days it not compliant .
        df.loc[((df["Days"].between(4, 7)) & (df["Severity"] == "Critical")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(10, 14)) & (df["Severity"] == "High")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(20, 30)) & (df["Severity"] == "Medium")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(40, 45)) & (df["Severity"] == "Low")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(55, 60)) & (df["Severity"] == "Minimal")), 'WithSLA'] = 1
        df.loc[((df["Days"].between(0, 100)) & (df["SLA Breached?"] == "Non-Compliant")), 'WithSLA'] = 2
        #TODO : we must check if the ticket status is closed or not to count it as breached sla or not (we can make one for closed and one for open)
        df.loc[df['WithSLA'] == 0, 'WithSLA'] = "Closed"
        df.loc[df['WithSLA'] == 1, 'WithSLA'] = "WithSLA"
        df.loc[df['WithSLA'] == 2, 'WithSLA'] = "Non-Compliant"

        st.markdown(f"""
                  <div class ="Card">
                        <div class="top-part">
                      <div class ="title">Within SLA</div>
                        </div>
                      <div class ="number" >{(df['WithSLA'] == 'WithSLA').sum()}</div>
                  </div>

                    """, unsafe_allow_html=True)
    with col7:
        st.markdown(f"""
                            <div class ="Card">
                                <div class="top-part">
                                <div class ="title">Breach SLA</div>
                                </div>
                                <div class ="number" >{(df['WithSLA'] == 'Non-Compliant').sum()}</div>
                            </div>

                              """, unsafe_allow_html=True)


def vulnerabilities_per_month(df):
    # Convert 'Date Last Found' to datetime

    df['Date Last Found'] = pd.to_datetime(df['Date Last Found'])
    df['Date Last Found'] = pd.to_datetime(df['Date Last Found'], format='%Y-%m-%d')

    df['month'] = df['Date Last Found'].dt.month
    month_mapping = {
        1: "January", 2: "February", 3: "March",
        4: "April", 5: "May", 6: "June",
        7: "July", 8: "August", 9: "September",
        10: "October", 11: "November", 12: "December"
    }
    # Extract month from 'Date Last Found' and map to month names

    df['month'] = df['month'].map(month_mapping)

    # Calculate counts of Applications per month and severity
    count_data = df.groupby(['month', 'Severity']).size().reset_index(name='Count')

    # Define color map for Severity levels
    color_map = {'Minimal': 'green', 'Low': '#6ED99D', 'Medium': 'orange', 'High': '#FF375E', 'Critical': 'red'}

    # Create a bar chart using Plotly Express
    fig = px.bar(count_data, x="month", y="Count", color='Severity',
                 height=400, color_discrete_map=color_map,
                 labels={'month': 'Month', 'Count': 'Number of Applications', 'Severity': 'Severity'})
    fig.update_xaxes(tickfont_color='#FFFFFF')
    fig.update_yaxes(tickfont_color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Vulnerabilities by Month </span>",
        'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': '#7233A3' , # Black background for the plot area with 0.7 transparency
        'legend': {
        'title': {
            'font': {'color': '#FFFFFF'}  # Set legend title color
        },
        'font': {'color': '#FFFFFF'}  # Set legend text color
    }

    })

    # Display the chart using Streamlit
    st.plotly_chart(fig)


def vulnerabilities_by_server(df):
    # Define the order of the categories
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Minimal']

    # Create an ordered categorical data type for the 'Severity' column
    df['Severity'] = pd.Categorical(df['Severity'], categories=severity_order, ordered=True)

    # Sort the DataFrame by the 'Severity' column
    df = df.sort_values('Severity')

    # Calculate counts for each severity level
    severity_counts = df['Severity'].value_counts(sort=False)

    colors = [
        'red' if severity == 'Critical' else '#FF375E' if severity == 'High' else 'orange' if severity == 'Medium' else '#6ED99D' if severity == 'Low' else 'green'
        for severity in severity_counts.index]

    # Create a pie chart using Plotly Express
    fig = go.Figure(data=[go.Pie(labels=severity_counts.index,
                                 values=severity_counts.values,
                                 textinfo='label+percent',
                                 insidetextorientation='radial',
                                 textposition='outside',
                                 marker=dict(colors=colors)
                                 )])

    # Update the layout of the chart
    fig.update_xaxes(color='#FFFFFF')
    fig.update_yaxes(color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Vulnerabilities by Severity </span>",
        # 'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity.
        'font': dict(color='#FFFFFF'),  # Change all text color to white
        'legend': {
            'title': {
                'font': {'color': '#FFFFFF'}  # Set legend title color
            },
            'font': {'color': '#FFFFFF'}  # Set legend text color
        }

    }

    )

    # Display the chart using Streamlit
    st.plotly_chart(fig)


def vulnerabilities_per_platform(df: DataFrame):
    """
    Display the vulnerabilities per platform
    :param df:
    :return:
    """
    keywords = df['Applications'].unique().tolist()
    df_closed = df[(df['Overall Status'] == 'Closed')]
    df_open = df[(df['Overall Status'] == 'Open')]
    df_not = df[(df['WithSLA'] == 'Non-Compliant')]

    #TODO double check here if the status is closed or not for the breached sla
    fig = go.Figure()

    fig.add_trace(
        go.Bar(x=keywords, y=df_closed.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Closed', marker_color='#90ee90', width=0.1))
    fig.add_trace(
        go.Bar(x=keywords, y=df_open.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Open', marker_color='#EACDFF', width=0.1))

    #TODO we need to make this for open tickets only
    fig.add_trace(
        go.Bar(x=keywords, y=df_not.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Non-Compliant', marker_color='#FF0000', width=0.1))

    fig.update_xaxes(tickfont_color='#FFFFFF')
    fig.update_yaxes(tickfont_color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Vulnerabilities by platform </span>",
        'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity
        'legend': {
            'title': {
                'font': {'color': '#FFFFFF'}  # Set legend title color
            },
            'font': {'color': '#FFFFFF'}  # Set legend text color
        }
    }

    )
    st.plotly_chart(fig)


def severity_distribution_by_platform(df: DataFrame):
    """
    Display the severity distribution by platform
    :param df:
    :return:
    """
    keywords = df['Applications'].unique().tolist()
    df_low = df[(df['Severity'] == 'Low')]
    df_med = df[(df['Severity'] == 'Medium')]
    df_high = df[(df['Severity'] == 'High')]
    df_critical = df[(df['Severity'] == 'Critical')]
    df_minimal = df[(df['Severity'] == 'Minimal')]

    fig = go.Figure()

    fig.add_trace(
        go.Bar(x=keywords,
               y=df_minimal.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Minimal',
               marker_color='green',
               width=0.1))
    fig.add_trace(
        go.Bar(x=keywords,
               y=df_low.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Low',
               marker_color='#6ED99D',
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
               marker_color='#FF375E',
               width=0.1))
    fig.add_trace(
        go.Bar(x=keywords,
               y=df_critical.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Critical',
               marker_color='red',
               width=0.1))

    fig.update_xaxes(tickfont_color='#FFFFFF')
    fig.update_yaxes(tickfont_color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Severity Distribution by Platform</span>",
        'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity
        'legend': {
            'title': {
                'font': {'color': '#FFFFFF'}  # Set legend title color
            },
            'font': {'color': '#FFFFFF'}  # Set legend text color
        }

    })
    st.plotly_chart(fig)


#TODO How we can know if it closed within the sla or not (we need to make this for only the closed tickets)

def closure_status(df: DataFrame):
    """
    Display the closure status
    :param df:
    :return:
    """
    sla_counts = df['WithSLA'].value_counts()
    colors = ['#6ED99D' if status == 'Closed' else '#ee2400' if status == 'Non-Compliant' else 'pink' for status in
              sla_counts.index]

    fig = go.Figure(data=[go.Pie(labels=sla_counts.index,
                                 values=sla_counts.values,
                                 textinfo='label+percent',
                                 insidetextorientation='radial',
                                 textposition='outside',
                                 marker=dict(colors=colors)
                                 )])

    fig.update_xaxes(tickfont_color='#FFFFFF')
    fig.update_yaxes(tickfont_color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Closure Status</span>",
        'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity
        'font': dict(color='#FFFFFF') , # Change all text color to white
        'legend': {
            'title': {
                'font': {'color': '#FFFFFF'}  # Set legend title color
            },
            'font': {'color': '#FFFFFF'}  # Set legend text color
        }

    })
    st.plotly_chart(fig)




def most_non_compliant_platforms(df: DataFrame):
    """
    Display the most non-compliant platforms
    :param df:
    :return:
    """
    # Filter the   rows with 'WithSLA' containing 'Non-Compliant'
    filtered_df = df[df['WithSLA'] == 'Non-Compliant']
    counts = filtered_df['Applications'].value_counts()
    fig = go.Figure()
    fig.add_trace(go.Bar(name='Applications', x=counts.index, y=counts.values,
                         marker_color='#6ED99D', width=0.3))

    fig.update_xaxes(tickfont_color='#FFFFFF')
    fig.update_yaxes(tickfont_color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Most Non-Compliant Platform</span>",
        'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity


    })
    st.plotly_chart(fig)




def statistics(df: DataFrame):
    """
    Display the statistics
    :param df:
    :return:
    """
    # Display statistics about the shown DataFrame
    # sla_less_equal_3_days = ((df['SLA Remaining Days'] <= 3) & (df['SLA Remaining Days'] > 0)).sum()
    # sla_more_than_3_days = (df['SLA Remaining Days'] > 3).sum()


    st.markdown("<h3 style='color:#FFFFFF'>Statistic</h2>", unsafe_allow_html=True)
    stats = {
        "Total Records": len(df),
        "Unique Applications": df['Applications'].nunique(),
        "Critical Vulnerabilities": (df['Severity'] == 'Critical').sum(),
        "High Vulnerabilities": (df['Severity'] == 'High').sum(),
        "Medium Vulnerabilities": (df['Severity'] == 'Medium').sum(),
        "Low Vulnerabilities": (df['Severity'] == 'Low').sum(),
        "Minimal Vulnerabilities": (df['Severity'] == 'Minimal').sum(),
        "SLA Breached": (df['SLA Breached?'] == 'Non-Compliant').sum(),
        # "SLA <= 3 Days": sla_less_equal_3_days,
        # "SLA > 3 Days": sla_more_than_3_days,

    }
    stats_df = pd.DataFrame(list(stats.items()), columns=['Statistic', 'Value'])
    nn = """
               <style>
               .st-emotion-cache-fwan7u{
                   color: #FFFFFF;
                    font-size: 23px
               }
            
               </style>
               """
    st.markdown(nn, unsafe_allow_html=True)
    st.table(stats_df.style.set_properties(**{'background-color': '#7233A3', 'color': '#FFFFFF','font-size':'17px'}))


# def platforms_close_to_sla_table(df: DataFrame):
#     """
#     Display the platforms close to SLA in a table
#     :param df:
#     :return:
#     """
#     st.markdown('<h2 class="title">PlatForm Close to SLA</h2>', unsafe_allow_html=True)
#
#     specific_columns = df[['Applications', 'Title', 'WithSLA', 'Severity', "Days", "SLA Remaining Days"]]
#
#     # Filter 'WithSLA' column to only include rows where the value is 'withSLA'
#     specific_columns = specific_columns[specific_columns['WithSLA'] == 'WithSLA']
#
#     # Create a container for the table and the pagination controls
#     container = st.container()
#
#     # Create columns for the previous page and next page buttons
#     prev_col, _, next_col = st.columns([1, 8, 1])
#
#     # Calculate the total number of pages
#     total_pages = len(specific_columns) // 10
#     if len(specific_columns) % 10 > 0:
#         total_pages += 1
#
#     # Get the current page number from the number input (default is 1)
#     page_number = st.number_input(label="Page Number", min_value=1, max_value=total_pages, value=1, step=1)
#
#     # Calculate the start and end indices for the rows on the current page
#     start = (page_number - 1) * 10
#     end = start + 10
#
#     # Display the table for the current page
#     container.table(specific_columns.iloc[start:end].reset_index(drop=True))



def app_os(df:DataFrame):
    red_hat_count = 0
    # Iterate through rows and update 'Title' column
    for index, row in df.iterrows():
        if 'Red Hat' in row['Title']:
            df.at[index, 'Title'] = 'Red Hat'
            red_hat_count += 1
        else:
            df.at[index, 'Title'] = 'Other'


    # Initialize counts
    red_hat_count = df[df['Title'].str.contains('Red Hat', case=False)].shape[0]
    other_count = df.shape[0] - red_hat_count

    # Create labels and values for pie chart
    labels = ['OS', 'Apllication']
    values = [red_hat_count, other_count]
    colors = ['#6ED99D', '#ee2400']  # Custom colors for Red Hat and Other

    # Create pie chart
    fig = go.Figure(data=[go.Pie(labels=labels,
                                 values=values,
                                 textinfo='label+percent',
                                 insidetextorientation='radial',
                                 textposition='outside',
                                 marker=dict(colors=colors)
                                 )])

    fig.update_xaxes(color='#FFFFFF')
    fig.update_yaxes(color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>App VS OS</span>",
        # 'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity.
        'font': dict(color='#FFFFFF'),  # Change all text color to white
        'legend': {
            'title': {
                'font': {'color': '#FFFFFF'}  # Set legend title color
            },
            'font': {'color': '#FFFFFF'}  # Set legend text color
        }

    })
    st.plotly_chart(fig)







def display_kpi(title, value, additional_info):
    st.markdown(f"""
        <div class="Card">
            <div class="top-part">
                <div class="title">{title}</div>
            </div>
            <div class="number">{value}</div>
            <div class="subtitle">{additional_info}</div>
        </div>
    """, unsafe_allow_html=True)




def compare_data(data_week1, data_week2):
    # Calculate counts for each severity level
    severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Minimal']
    counts_week1 = {level: data_week1[data_week1['Severity'] == level].shape[0] for level in severity_levels}
    counts_week2 = {level: data_week2[data_week2['Severity'] == level].shape[0] for level in severity_levels}

    # Display KPIs/cards in the header


    # Display KPIs for Week 1
    col1, col2, col3, col4, col5,col6 = st.columns(6)

    with col1:
        display_kpi("Total", len(data_week2), f"{len(data_week1)} Week1")

    with col2:
        display_kpi("Critical Week 2", counts_week2['Critical'], f"{(data_week1['Severity'] == 'Critical').sum()} Week1")
    with col3:
        display_kpi("High Week 2", counts_week2['High'], f"{(data_week1['Severity'] == 'High').sum()} Week1")
    with col4:
        display_kpi("Medium Week 2", counts_week2['Medium'], f"{(data_week1['Severity'] == 'Medium').sum()} Week1")
    with col5:
        display_kpi("Low Week 2", counts_week2['Low'], f"{(data_week1['Severity'] == 'Low').sum()} Week1")
    with col6:
        display_kpi("Minimal Week 2", counts_week2['Minimal'], f"{(data_week1['Severity'] == 'Minimal').sum()} Week1")


    fig = go.Figure(data=[
        go.Bar(name='Week 1', x=severity_levels, y=[counts_week1[level] for level in severity_levels]),
        go.Bar(name='Week 2', x=severity_levels, y=[counts_week2[level] for level in severity_levels])
    ])

    # Update layout and display the chart
    fig.update_xaxes(tickfont_color='#FFFFFF')
    fig.update_yaxes(tickfont_color='#FFFFFF')
    fig.update_layout({
        'title': "<span style='color:#FFFFFF; font-size:20px ; text-align:left;'>Severity Comparison Between Weeks</span>",
        'plot_bgcolor': '#7233A3',  # Background color for the plot area
        'paper_bgcolor': 'rgba(114, 51, 163, 1)',  # Purple background for the plot area with 0.4 opacity

    })
    st.plotly_chart(fig)

