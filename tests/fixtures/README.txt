FORMAT-TEST FIXTURES ONLY.
These few lines exist so `python -m unittest` can check that the parsers understand the
log formats of Suricata (eve.json), Snort 3 (alert_json) and Snort alert_fast.
They are NOT used by the pipeline and must never be used for results.
Real alerts come exclusively from Snort/Suricata running on the CICIDS2017 pcaps.
