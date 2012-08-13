LIBUMBERLOG_0.3.0 {
	global:
        # Our own symbols
          ul_format;
          ul_vformat;
          ul_syslog;
          ul_vsyslog;
          ul_legacy_syslog;
          ul_legacy_vsyslog;
          ul_openlog;
          ul_closelog;
          ul_setlogmask;
          ul_set_log_flags;

	local:
        # Inherited from elsewhere, but should not be exported
          facilitynames;
          prioritynames;
};
