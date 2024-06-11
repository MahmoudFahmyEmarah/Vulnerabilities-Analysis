import pandas as pd
import streamlit as st
from plotly import graph_objects as go, express as px



def KPI(df):
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

    # this col talk about KPI with servity , LOW , Medium , High ,Critical etc

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
        Low = (df['Severity'] == 'Low').sum()
        st.markdown(f"""
                     <div class ="Card">
                        <div class="top-part">
                      <h3 class ="text">Low</h3>
                        </div>
                       <h4 class ="statistic">{Low}</h4>
                        <h5 class ="statistic">132 Servers</h4>




               </div>

                   """, unsafe_allow_html=True)

    with col6:
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


def Vulnerabilities_chart(df):
    keywords = df['Applications'].unique().tolist()
    df_closed = df[(df['Overall Status'] == 'Closed')]
    df_open = df[(df['Overall Status'] == 'Open')]
    df_not = df[(df['WithSLA'] == 'Non-Compliant')]
    df_breached = df[(df['SLA Breached?'] == 'Non-Compliant')]
    #print count the open tickets
    print(df['Overall Status'].value_counts())
    fig = go.Figure()

    fig.add_trace(
        go.Bar(x=keywords, y=df_closed.groupby('Applications').size().reindex(keywords, fill_value=0), name='Closed',
               marker_color='#008000', width=0.1))  # Dark Green
    fig.add_trace(
        go.Bar(x=keywords, y=df_not.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Non-Compliant', marker_color='#90ee90', width=0.1))  # Light Green

    fig.add_trace(
        go.Bar(x=keywords, y=df_open.groupby('Applications').size().reindex(keywords, fill_value=0), name='Open',
               marker_color='#FF6347', width=0.1))  # Light Red

    fig.add_trace(
        go.Bar(x=keywords, y=df_breached.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='SLA Breached', marker_color='#FF0000', width=0.1))  # Dark Red

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Vulnerabilities per platform</span>",
        xaxis_title='Platform',
        yaxis_title='Values',
    )

    # Display the chart using Streamlit
    st.plotly_chart(fig)


def Cluster_status(df):
    #Cluster Chart with any vulnerabilities close to SLA
    sla_counts = df['WithSLA'].value_counts()
    fig = px.pie(names=sla_counts.index, values=sla_counts.values, labels=sla_counts.index,
                 title="<span style='color:#600587; font-size:20px'>Cluster Status </span>", hole=0.3,
                 color_discrete_sequence=[
                     "#6ED99D" if status == "Closed" else "pink" if status == "Non-Compliant" else "red" for status in
                     sla_counts.index])
    # Show the chart
    st.plotly_chart(fig)


def Platforms_chart(df):
    st.markdown('<h2 class="title">PlatForm Close to SLA</h2>', unsafe_allow_html=True)

    specific_columns = df[['Applications', 'Title', 'WithSLA', 'Severity', "Days", "SLA Remaining Days"]]

    # Filter 'WithSLA' column to only include rows where the value is 'withSLA'
    specific_columns = specific_columns[specific_columns['WithSLA'] == 'WithSLA']
    st.table(specific_columns.reset_index(drop=True))


def Platform_chart_NonCompliant(df):
    # Filter the   rows with 'WithSLA' containing 'Non-Compliant'
    filtered_df = df[df['WithSLA'] == 'Non-Compliant']
    counts = filtered_df['Applications'].value_counts()

    fig = px.bar(x=counts.index, y=counts.values, labels={'x': 'Applications', 'y': 'Count'},
                 title="<span style='color:#600587; font-size:20px'>Most Non-Compliant Platform</span>",
                 color_discrete_sequence=['#6ED99D'])


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
    df_medin = df[(df['Severity'] == 'Minimal')]

    fig = go.Figure()

    fig.add_trace(
        go.Bar(x=keywords,
               y=df_low.groupby('Applications').size().reindex(keywords, fill_value=0),
               name='Low',
               marker_color= '#6ED99D',
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
               marker_color='green',
               width=0.1))

    fig.update_layout(
        title="<span style='color:#600587; font-size:20px'>Severity Distribution by Platform</span>",
        xaxis_title='Platform',
        yaxis_title='Values',
    )
    #
    # Display the chart using Streamlit
    st.plotly_chart(fig)
