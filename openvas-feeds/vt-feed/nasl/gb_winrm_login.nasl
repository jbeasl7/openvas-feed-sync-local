# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136995");
  script_version("2026-10-09T05:51:24+0000");
  script_tag(name:"last_modification", value:"2026-10-09 05:51:24 +0000 (Fri, 09 Oct 2026)");
  script_tag(name:"creation_date", value:"2026-03-24 13:57:27 +0000 (Tue, 24 Mar 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Windows Remote Management (WinRM) Detection and Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Windows");

  # Don't add a dependency to os_detection.nasl, smb_reg_service_pack.nasl, smb_registry_access.nasl
  # future PR:
  #   "winrm_ntlm_authorization.nasl", "winrm_krb5_authorization.nasl");
  script_dependencies("logins.nasl", "lsc_options.nasl", "smb_authorization.nasl",
                      "krb5_authorization.nasl", "smb_login.nasl", "smb_nativelanman.nasl",
                      "global_settings.nasl");

  # nb: since there's no way to OR either require_keys or KB-key names (via mandatory_keys)
  #     for now copying those from smb_login. Probably will have to add a KB-key
  #     signalling whether any of the potential credential
  script_require_keys("WinRM/login_filled");
  script_exclude_keys("global_settings/authenticated_scans_disabled");

  # nb: cannot require ports in case of user-changed endpoints in the future
  # but by default would be 5985 or 5986
  script_tag(name:"summary", value:"Detects and verifies credential correctness for using
  WinRM");
  # Via authenticated login and all
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/windows/win32/winrm/portal");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management");

  exit(0);
}

# nb:
# For includes the only required one is host_details.inc, all other includes depend on the individual detection
include("host_details.inc");
include("port_service_func.inc");
include("winrm_func.inc");
include("powershell_func.inc");
# nb: for GOS-& Scanner-version check
include("misc_func.inc");
include("version_func.inc");
# nb: for log-level checks, s.t. that we won't have to import it in all
#     powershell-using NASLs
include("global_settings.inc");

# nb: Don't add these as a exclusiding kb-keys as this would prevent the logging and
#     related new KB-keys below.
if ( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) {
  set_kb_item( name:"WinRM/failure", value:TRUE );
  set_kb_item( name:"login/WinRM/failed/reason", value:"Authenticated Scans disabled" );
  exit( 0 );
}

if ( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) {
  log_message( data:"Windows Remote Management Error: win_cmd_exec usage is disabled in scan configuration. Skipping tests for it.", port:0 );
  set_kb_item( name:"WinRM/failure", value:TRUE );
  set_kb_item( name:"login/WinRM/failed/reason", value:"win_cmd_exec disabled" );
  exit( 0 );
}


if ( get_kb_item( "WinRM/login/disabled" ) ) {
  # failure keys set in logins.nasl to ensure never executes irrespective of inclusion of
  # gb_winrm_login.nasl in the scan config
  exit( 0 );
}

# nb: cannot be an isnull check!
if ( gos_vers = get_local_gos_version() ) {
  if ( version_is_less( version:gos_vers, test_version:"25.0.8" ) ) {
    log_message(data:"WinRM requires GOS >= 25.0.8. Please update GOS to use WinRM for authenticated scans.", port:0 );
    set_kb_item( name:"WinRM/failure", value:TRUE );
    set_kb_item( name:"login/WinRM/failed/reason", value:"Insufficient GOS version" );
    exit( 0 );
  }
} else if ( version_is_less( version:OPENVAS_VERSION, test_version:"23.50.17") ) {
  log_message(data:"WinRM requires the scanner version 23.50.17 or later. Please update your scanner to use WinRM for authenticated scans.", port:0 );
  set_kb_item( name:"WinRM/failure", value:TRUE );
  set_kb_item( name:"login/WinRM/failed/reason", value:"Insufficient scanner version" );
  exit( 0 );
}

# nb: do so before calling any winrm_func.inc etc. internals
if ( debug_level )
  set_kb_item( name:"WinRM/debug_enabled", value:TRUE );

credential_type = parse_winrm_credentials();

connect_info = kb_winrm_connectinfo();

# could also be return value or sth.
if ( credential_type == "Kerberos" )
  prepare_kerberos();


# nb: Must be set before initial command to ensure already used
#     for failures due to scanner-bug in initial command
#     version-check to be added once version with confirmed fix is known
set_kb_item( name:"WinRM/result_double_check", value:"yes" );

# nb: must be run before KB-keys are read for reporting to ensure
#     properly populated in case of fallbacks / default usage
res = winrm_powershell_prompt( cmd:"netstat" );


protocol_info = "";

port = kb_winrm_port();
login = kb_winrm_login();

auth_info = "via the " + credential_type + " credentials.";


if ( isnull( res ) || ! strlen( res ) ) {
  error_message( data:"Windows Remote Management Error: Failure while running test command for WinRM. Skipping tests requiring WinRM.", port:0 );

  failure_kind = get_kb_item( "login/WinRM/failure/kind" );
  if ( failure_kind == "login" || failure_kind == "SSL" || failure_kind == "Connection" ) {
    reason = "It was NOT possible to log into the remote host using the WinRM protocol";
    protocol_info = " due to a connection or credential problem. This can also be caused by a stopped / disabled WinRM service on the target machine.";

    if ( credential_type == "Kerberos" ) {
      if ( ! isnull( get_kb_item( "login/WinRM/NTLM/success" ) ) ) {
        auth_info += " Using them for both Kerberos and the following NTLM-based fallback was unsuccessful.";
      }
    }

  } else if ( failure_kind == "CLI / library calling" ) {
    reason = "It was NOT possible to use WinRM due to an unknown internal CLI / library error.";
  } else if ( failure_kind =~ "^PS/CMD interpreter" ) {
    reason = "It was potentially possible to log into the remote host using the WinRM protocol, but either the server or a library component produced an error while executing a test command.";
  } else {
    reason += "It was NOT possible to use WinRM: '" + failure_kind + "'.";
  }
  reason += protocol_info;

  if ( fallback_log = chomp( __winrm_fallback_log ) )
    reason += '\n' + fallback_log + '\n';
  reason += " Please check the remaining log and error messages for more information.";

  replace_kb_item( name:"WinRM/failure", value:TRUE );
  set_kb_item( name:"login/WinRM/failed", value:TRUE );
  set_kb_item( name:"login/WinRM/failed/reason", value:reason );


} else {
  replace_kb_item( name:"WinRM/success", value:TRUE );
  # nb: only until winrm_{krb5,ntlm}_authorization.nasl are not in the feed yet

  register_host_detail( name:"Auth-WinRM-Success", value:"Protocol WinRM, Port " + port + ", User " + login );
  service_register( port:port, proto:"WinRM" );

  if ( credential_type == "Kerberos" && get_kb_item( "login/WinRM/NTLM/success" ) )
        auth_info += " Using them for Kerberos was unsuccessful, but a fallback to NTLM-based authentication was and will be used for future connections.";

  reason = "It was possible to log into the remote host using the WinRM protocol " + auth_info;
  set_kb_item( name:"login/WinRM/success/reason", value:reason + " A sample 'netstat' command was executed successfully." );
  reason += " A sample 'netstat' command was executed successfully with the following results:'" + '\n' + res + "'";

  if ( fallback_log = chomp( __winrm_fallback_log ) )
    reason += '\nLogin fallback log:\n' + fallback_log;
}

if ( fallback_log )
  set_kb_item( name:"login/WinRM/fallback_log", value:fallback_log );

log_message( port:port, data:reason + '\nError backlog during login:\n' + __winrm_reason_log );

exit( 0 );
