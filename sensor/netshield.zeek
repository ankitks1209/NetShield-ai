## NetShield sensor logging. Logs summaries and health; no packet payload capture.
@load policy/misc/stats
@load policy/misc/capture-loss

redef LogAscii::use_json = T;
redef Stats::report_interval = 10sec;
redef CaptureLoss::initial_watch_interval = 10sec;
redef CaptureLoss::watch_interval = 30sec;
