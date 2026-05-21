"""Dashboard SOC BioCybe (Phase 2.3.c) — UI de triage en lecture seule.

Construit une app Dash à partir de la couche `data.py`. Affiche :
  - Cartes KPI : quarantaine, audit, threat intel
  - Onglet Quarantaine : table + répartitions famille/sévérité
  - Onglet Audit : intégrité de chaîne + table + actions
  - Onglet Threat Intel : fraicheur des feeds + compteurs IOC

Auto-refresh via `dcc.Interval`. Lecture seule : aucune action
destructive depuis l'UI (la remédiation passe par CLI/API avec audit
trail). Pensé pour tourner derrière un reverse-proxy authentifié ou
sur un réseau d'admin isolé — pas d'auth applicative ici par défaut,
on bind sur 127.0.0.1.

Servi en prod via waitress (Windows) / le serveur WSGI au choix sous
Linux. `dash.Dash` expose `.server` (Flask) pour un déploiement WSGI
standard.

Les imports Dash sont faits dans `create_dashboard()` pour que
`import biocybe.dashboard` ne casse pas si l'extra `[web]` n'est pas
installé.
"""

from __future__ import annotations

import logging

from .data import DashboardConfig, DashboardData

logger = logging.getLogger("biocybe.dashboard")

# Palette sévérité → couleur (cohérente avec les conventions SOC)
_SEVERITY_COLORS = {
    "critical": "#b00020",
    "high": "#e65100",
    "medium": "#f9a825",
    "low": "#2e7d32",
    "inconnue": "#616161",
    "none": "#2e7d32",
}


class DashboardUnavailable(RuntimeError):
    """Levée si les dépendances Dash ne sont pas installées."""


def create_dashboard(config: DashboardConfig | None = None, *, refresh_seconds: int = 15):
    """Construit et retourne l'app Dash.

    Raises:
        DashboardUnavailable: si dash/plotly/dbc ne sont pas installés.
    """
    try:
        import dash_bootstrap_components as dbc
        import plotly.graph_objects as go
        from dash import Dash, Input, Output, dash_table, dcc, html
    except ImportError as exc:
        raise DashboardUnavailable(
            "Dépendances dashboard absentes. Installe : pip install biocybe[web]"
        ) from exc

    config = config or DashboardConfig()
    data = DashboardData(config)

    app = Dash(
        __name__,
        title="BioCybe SOC",
        external_stylesheets=[dbc.themes.DARKLY],
        update_title=None,
    )

    # ------------------------------------------------------------------
    # Helpers de rendu
    # ------------------------------------------------------------------

    def _kpi_card(title: str, value, color: str = "#1565c0", subtitle: str = ""):
        return dbc.Card(
            dbc.CardBody(
                [
                    html.Div(title, style={"fontSize": "0.85rem", "opacity": 0.7}),
                    html.Div(
                        str(value),
                        style={"fontSize": "2rem", "fontWeight": "bold", "color": color},
                    ),
                    html.Div(subtitle, style={"fontSize": "0.75rem", "opacity": 0.6}),
                ]
            ),
            className="m-1",
        )

    def _bar(mapping: dict, title: str, color: str = "#42a5f5"):
        keys = list(mapping.keys())
        vals = list(mapping.values())
        fig = go.Figure(go.Bar(x=keys, y=vals, marker_color=color))
        fig.update_layout(
            title=title,
            template="plotly_dark",
            margin=dict(l=20, r=20, t=40, b=20),
            height=300,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        return fig

    def _table(rows: list[dict], columns: list[str]):
        return dash_table.DataTable(
            data=rows,
            columns=[{"name": c, "id": c} for c in columns],
            page_size=15,
            filter_action="native",
            sort_action="native",
            style_table={"overflowX": "auto"},
            style_cell={
                "backgroundColor": "#222",
                "color": "#eee",
                "fontSize": "0.8rem",
                "textAlign": "left",
                "maxWidth": "320px",
                "overflow": "hidden",
                "textOverflow": "ellipsis",
            },
            style_header={"backgroundColor": "#111", "fontWeight": "bold"},
        )

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    app.layout = dbc.Container(
        fluid=True,
        children=[
            dcc.Interval(id="refresh", interval=refresh_seconds * 1000, n_intervals=0),
            html.Div(
                [
                    html.H2("BioCybe — Console SOC", className="mt-3"),
                    html.Div(
                        "Triage en lecture seule · auto-refresh "
                        f"{refresh_seconds}s · remédiation via CLI/API",
                        style={"opacity": 0.6, "fontSize": "0.8rem"},
                    ),
                ]
            ),
            html.Div(id="kpi-row", className="d-flex flex-wrap my-2"),
            dbc.Tabs(
                [
                    dbc.Tab(label="Quarantaine", tab_id="tab-quarantine"),
                    dbc.Tab(label="Audit", tab_id="tab-audit"),
                    dbc.Tab(label="Threat Intel", tab_id="tab-intel"),
                    dbc.Tab(label="Mémoire", tab_id="tab-memory"),
                ],
                id="tabs",
                active_tab="tab-quarantine",
            ),
            html.Div(id="tab-content", className="mt-3"),
        ],
    )

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    @app.callback(Output("kpi-row", "children"), Input("refresh", "n_intervals"))
    def _update_kpis(_n):
        o = data.overview()
        sev_color = _SEVERITY_COLORS.get(o["quarantine_worst_severity"], "#616161")
        chain = o["audit_chain_ok"]
        chain_label = "intègre" if chain else ("ALTÉRÉE" if chain is False else "n/a")
        chain_color = "#2e7d32" if chain else ("#b00020" if chain is False else "#616161")
        intel_color = "#b00020" if o["intel_any_stale"] else "#2e7d32"
        intel_sub = (
            "feeds stale !"
            if o["intel_any_stale"]
            else ("aucun feed" if o["intel_all_missing"] else "feeds frais")
        )
        return [
            _kpi_card(
                "Quarantaine",
                o["quarantine_total"],
                sev_color,
                f"pire sévérité : {o['quarantine_worst_severity']}",
            ),
            _kpi_card("Audit (entrées)", o["audit_total"], chain_color, f"chaîne {chain_label}"),
            _kpi_card("IOCs chargés", o["intel_total_iocs"], intel_color, intel_sub),
        ]

    @app.callback(
        Output("tab-content", "children"),
        Input("tabs", "active_tab"),
        Input("refresh", "n_intervals"),
    )
    def _render_tab(active_tab, _n):
        if active_tab == "tab-audit":
            return _render_audit()
        if active_tab == "tab-intel":
            return _render_intel()
        if active_tab == "tab-memory":
            return _render_memory()
        return _render_quarantine()

    def _render_quarantine():
        q = data.quarantine_summary()
        charts = dbc.Row(
            [
                dbc.Col(dcc.Graph(figure=_bar(q["by_severity"], "Par sévérité", "#ef5350")), md=4),
                dbc.Col(dcc.Graph(figure=_bar(q["by_family"], "Par famille", "#ab47bc")), md=4),
                dbc.Col(
                    dcc.Graph(figure=_bar(q["by_detector"], "Par cellule détectrice", "#26a69a")),
                    md=4,
                ),
            ]
        )
        cols = [
            "quarantined_at",
            "severity",
            "family",
            "detected_by",
            "original_path",
            "reason",
            "size_bytes",
            "encrypted",
        ]
        return html.Div([charts, html.H5("Entrées récentes"), _table(q["table"], cols)])

    def _render_audit():
        a = data.audit_summary()
        if not a["exists"]:
            return dbc.Alert(
                "Aucun audit log trouvé. Active-le dans config/biocybe.yaml "
                "(audit.enabled: true).",
                color="secondary",
            )
        chain_banner = (
            dbc.Alert("Chaîne d'audit intègre ✓", color="success")
            if a["chain_ok"]
            else dbc.Alert(
                ["Chaîne d'audit ALTÉRÉE ✗ : ", html.Code(", ".join(a["chain_errors"][:5]))],
                color="danger",
            )
        )
        charts = dbc.Row(
            [
                dbc.Col(dcc.Graph(figure=_bar(a["by_action"], "Par action", "#42a5f5")), md=6),
                dbc.Col(dcc.Graph(figure=_bar(a["by_outcome"], "Par résultat", "#66bb6a")), md=6),
            ]
        )
        cols = ["seq", "ts", "actor", "action", "outcome", "details"]
        return html.Div(
            [chain_banner, charts, html.H5("Événements récents"), _table(a["table"], cols)]
        )

    def _render_intel():
        i = data.intel_summary()
        banner = None
        if i["all_missing"]:
            banner = dbc.Alert(
                "Aucun feed récupéré. Lance : biocybe intel update --source all",
                color="secondary",
            )
        elif i["any_stale"]:
            banner = dbc.Alert(
                "Au moins un feed est stale — relance le refresh.", color="warning"
            )
        else:
            banner = dbc.Alert("Tous les feeds sont frais ✓", color="success")

        charts = dbc.Row(
            [
                dbc.Col(
                    dcc.Graph(figure=_bar(i["lookup_by_type"], "IOCs par type", "#ffa726")), md=6
                ),
                dbc.Col(
                    dcc.Graph(
                        figure=_bar(
                            {f["source"]: (f["age_seconds"] or 0) for f in i["feeds"]},
                            "Âge des feeds (secondes)",
                            "#ec407a",
                        )
                    ),
                    md=6,
                ),
            ]
        )
        cols = ["source", "label", "last_update", "age_human", "ioc_count", "stale"]
        return html.Div([banner, charts, html.H5("Feeds"), _table(i["feeds"], cols)])

    def _render_memory():
        m = data.memory_summary()
        if not m["exists"]:
            return dbc.Alert(
                "Mémoire immunitaire non initialisée. Active-la dans la config "
                "(memory.enabled: true) ou via les scans/daemon.",
                color="secondary",
            )
        fp_count = m["by_disposition"].get("confirmed_benign", 0)
        banner = dbc.Alert(
            f"{m['total']} indicateurs mémorisés · "
            f"{fp_count} faux positifs supprimés · réponse secondaire active",
            color="info",
        )
        charts = dbc.Row(
            [
                dbc.Col(dcc.Graph(figure=_bar(m["by_verdict"], "Par verdict", "#ef5350")), md=4),
                dbc.Col(
                    dcc.Graph(figure=_bar(m["by_disposition"], "Par disposition", "#42a5f5")),
                    md=4,
                ),
                dbc.Col(
                    dcc.Graph(
                        figure=_bar(dict(m["top_families"]), "Top familles", "#ab47bc")
                    ),
                    md=4,
                ),
            ]
        )
        cols = [
            "indicator",
            "type",
            "verdict",
            "family",
            "times_seen",
            "confidence",
            "disposition",
            "last_seen",
        ]
        return html.Div(
            [banner, charts, html.H5("Indicateurs (les plus vus)"), _table(m["table"], cols)]
        )

    return app


def serve_dashboard(
    config: DashboardConfig | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 8050,
    refresh_seconds: int = 15,
    debug: bool = False,
) -> None:
    """Lance le dashboard via un serveur WSGI de production.

    Sous Windows : waitress. Sous Linux/macOS : waitress aussi si
    présent (dépendance optionnelle), sinon le serveur Dash intégré
    en dernier recours (avec warning).
    """
    app = create_dashboard(config, refresh_seconds=refresh_seconds)
    flask_server = app.server

    if debug:
        logger.warning("Dashboard en mode debug — NE PAS utiliser en production.")
        app.run(host=host, port=port, debug=True)
        return

    try:
        from waitress import serve as waitress_serve

        logger.info("Dashboard BioCybe sur http://%s:%d (waitress)", host, port)
        waitress_serve(flask_server, host=host, port=port)
    except ImportError:
        logger.warning(
            "waitress absent — fallback serveur Dash intégré (non recommandé en prod). "
            "Installe : pip install biocybe[web]"
        )
        app.run(host=host, port=port, debug=False)


__all__ = [
    "DashboardConfig",
    "DashboardUnavailable",
    "create_dashboard",
    "serve_dashboard",
]
