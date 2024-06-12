import pandas as pd
import streamlit as st
from pandas import DataFrame
from plotly import graph_objects as go


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
                    <h3 class ="text">Total</h3>
                </div>
                <h4 class ="statistic">{total}</h4>
                <h5 class ="statistic">164 Servers</h5>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        critical = (df['Severity'] == 'Critical').sum()
        st.markdown(f"""
                     <div class ="Card" style="background-color: #FF0000;">
                            <h3 class ="text">Critical</h3>
                            <h4 class ="text" >{critical}</h4>
               </div>
                   """, unsafe_allow_html=True)
    with col3:
        high = (df['Severity'] == 'High').sum()
        st.markdown(f"""
                     <div class ="Card" style="background-color: #FF0000;">
                      <h3 class ="text">High</h3>
                       <h4 class ="text" >{high}</h4>
               </div>

                   """, unsafe_allow_html=True)
    with col4:
        medium = (df['Severity'] == 'Medium').sum()
        st.markdown(f"""
                     <div class ="Card">
                     <div class="top-part">
                      <h3 class ="text">Medium</h3>
                      </div>
                       <h4 class ="statistic" >{medium}</h4>
                       <h5 class ="statistic">20 Servers</h4>
               </div>

                   """, unsafe_allow_html=True)
    with col5:
        low = (df['Severity'] == 'Low').sum()
        st.markdown(f"""
                     <div class ="Card">
                        <div class="top-part">
                      <h3 class ="text">Low</h3>
                        </div>
                       <h4 class ="statistic">{low}</h4>
                        <h5 class ="statistic">132 Servers</h4>
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
                      <h3 class ="text">Within SLA</h3>
                        </div>
                      <h4 class ="statistic" >{(df['WithSLA'] == 'WithSLA').sum()}</h4>
                  </div>

                    """, unsafe_allow_html=True)
    with col7:
        st.markdown(f"""
                            <div class ="Card">
                                <div class="top-part">
                                <h3 class ="text">Breach SLA</h3>
                                </div>
                                <h4 class ="statistic" >{(df['WithSLA'] == 'Non-Compliant').sum()}</h4>
                            </div>

                              """, unsafe_allow_html=True)


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

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Vulnerabilities per platform</span>",
        xaxis_title='Platform',
        yaxis_title='Values',
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

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Severity Distribution by Platform</span>",
        xaxis_title='Platform',
        yaxis_title='Values',
    )
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

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Closure Status </span>",
    )

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

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Most Non-Compliant Platform</span>",
        xaxis_title='Applications',
        yaxis_title='Count',
    )

    # Show the chart
    st.plotly_chart(fig)


def statistics(df: DataFrame):
    """
    Display the statistics
    :param df:
    :return:
    """
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


def platforms_close_to_sla_table(df: DataFrame):
    """
    Display the platforms close to SLA in a table
    :param df:
    :return:
    """
    st.markdown('<h2 class="title">PlatForm Close to SLA</h2>', unsafe_allow_html=True)

    specific_columns = df[['Applications', 'Title', 'WithSLA', 'Severity', "Days", "SLA Remaining Days"]]

    # Filter 'WithSLA' column to only include rows where the value is 'withSLA'
    specific_columns = specific_columns[specific_columns['WithSLA'] == 'WithSLA']
    st.table(specific_columns.reset_index(drop=True))
