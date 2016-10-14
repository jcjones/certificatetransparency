from moztelemetry.spark import get_pings

pings = get_pings(None, app="Firefox", channel="release", build_id="*")
properties = get_pings_properties()
# histories = get_clients_history(sc, fraction = 0.01)