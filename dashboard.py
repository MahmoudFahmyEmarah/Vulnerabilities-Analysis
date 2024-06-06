import dash
from dash import Dash, html, dcc, callback, Output, Input
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import pandas as pd

# Dummy Data
total_vulnerabilities = 8109
closed_vulnerabilities = 3900
open_vulnerabilities = 4209
breached_sla = 24.64
within_sla = 1.98
closed_percentage = 73.39
critical_open = 0
high_open = 0
medium_open = 20
low_open = 4189
sla_open = 113

# Data for Vulnerabilities per Platform
platform_data = {
    'Platform': ['R-Studio', 'Data Lake', 'CDP Workers', 'Cloudera', 'Nifi', 'Airflow'],
    'Closed': [1500, 398, 427, 288, 132, 400],
    'Open': [1200, 400, 428, 300, 120, 450]
}
df_platform = pd.DataFrame(platform_data)

# Initialize the app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H2('Vulnerabilities (YTD)', className='text-center text-primary mb-4')
            ]),
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.H5('Total Vulnerabilities', className='card-title'),
                        html.H3(f'{total_vulnerabilities}', className='card-text text-center text-primary'),
                        html.H5(f'{closed_vulnerabilities} Closed', className='text-success text-center'),
                        html.H5(f'{open_vulnerabilities} Open', className='text-danger text-center')
                    ])
                ], className='mb-4')
            ]),
            html.Div([
                dcc.Graph(
                    id='closure-status-pie',
                    figure={
                        'data': [
                            go.Pie(
                                labels=['Closed', 'Breached SLA', 'Within SLA'],
                                values=[closed_percentage, breached_sla, within_sla],
                                marker=dict(colors=['green', 'red', 'yellow']),
                                hole=.4
                            )
                        ],
                        'layout': go.Layout(
                            title='Closure Status',
                            showlegend=True
                        )
                    }
                )
            ])
        ], width=4),
        dbc.Col([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H6('Critical', className='card-title'),
                            html.H3(f'{critical_open}', className='text-center text-primary')
                        ])
                    ], className='text-danger mb-2', style={'border-radius': '15px', 'background-color': '#ffcccc'})
                ]),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H6('High', className='card-title'),
                            html.H3(f'{high_open}', className='text-center text-primary')
                        ])
                    ], className='text-danger mb-2', style={'border-radius': '15px', 'background-color': '#ffcccc'})
                ]),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H6('Medium', className='card-title'),
                            html.H3(f'{medium_open}', className='text-center text-primary')
                        ])
                    ], className='mb-2', style={'border-radius': '15px', 'background-color': '#e0e0e0'})
                ]),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H6('Low', className='card-title'),
                            html.H3(f'{low_open}', className='text-center text-primary')
                        ])
                    ], className='mb-2', style={'border-radius': '15px', 'background-color': '#e0e0e0'})
                ]),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H6('SLA', className='card-title'),
                            html.H3(f'{sla_open}', className='text-center text-primary')
                        ])
                    ], className='mb-2', style={'border-radius': '15px', 'background-color': '#e0e0e0'})
                ])
            ]),
            dcc.Graph(
                id='vulnerabilities-per-platform-bar',
                figure={
                    'data': [
                        go.Bar(
                            name='Closed',
                            x=df_platform['Platform'],
                            y=df_platform['Closed'],
                            marker=dict(color='green')
                        ),
                        go.Bar(
                            name='Open',
                            x=df_platform['Platform'],
                            y=df_platform['Open'],
                            marker=dict(color='red')
                        )
                    ],
                    'layout': go.Layout(
                        title='Vulnerabilities per Platform',
                        barmode='group'
                    )
                }
            )
        ], width=8)
    ])
], fluid=True)

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
