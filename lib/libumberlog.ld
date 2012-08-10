LIBUMBERLOG_0.1.0 {
	global:
        # Our own symbols
          ul_format;
          ul_vformat;
          ul_syslog;
          ul_vsyslog;
          ul_legacy_syslog;
          ul_legacy_vsyslog;
          ul_openlog;
          ul_setlogmask;

	local:
        # Inherited from elsewhere, but should not be exported
          facilitynames;
          prioritynames;
};

LIBUMBERLOG_0.2.1 {
	global:
          ul_closelog;
} LIBUMBERLOG_0.1.0;

LIBUMBERLOG_0.3.0 {
	global:
          ul_set_log_flags;
} LIBUMBERLOG_0.2.1;
