# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108162");
  script_version("2025-07-31T05:44:45+0000");
  script_tag(name:"last_modification", value:"2025-07-31 05:44:45 +0000 (Thu, 31 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-10-17 10:31:00 +0200 (Tue, 17 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Authenticated Scan / LSC Info Consolidation (Linux/Unix SSH Login)");
  # nb: Needs to run at the end of the scan due to the required info only available in this phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "ssh_login_failed.nasl", "global_settings.nasl",
                      "gb_gather_hardware_info_ssh_login.nasl", "lsc_options.nasl",
                      "ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-24.10/en/scanning.html#requirements-on-target-systems-with-linux-unix");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#requirements-on-target-systems-with-linux-unix");

  script_tag(name:"summary", value:"Consolidation and reporting of various technical information
  about authenticated scans / local security checks (LSC) via SSH for Linux/Unix targets.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

info_array = make_array();
# nb: key is the KB item, value the description used in the report
# The order doesn't matter, this will be sorted later in text_format_table()
kb_array = make_array( "ssh/login/uname", "Response to 'uname -a' command",
                       "ssh/login/freebsdpatchlevel", "FreeBSD patchlevel",
                       "ssh/login/freebsdrel", "FreeBSD release",
                       "ssh/login/freebsdpkg/available", "FreeBSD package management tool available",
                       "ssh/login/openbsdversion", "OpenBSD version",
                       "ssh/login/osx_name", "Mac OS X release name",
                       "ssh/login/osx_build", "Mac OS X build",
                       "ssh/login/osx_version", "Mac OS X version",
                       "ssh/login/solhardwaretype", "Solaris hardware type",
                       "ssh/login/solosversion", "Solaris version",
                       "ssh/login/failed_rpm_db_access", "rpm: Access to the RPM database failed",
                       "ssh/login/release", "Operating System Key (used for e.g. classic Local Security Checks)",
                       "ssh/login/release_notus", "Operating System Key (used for Notus based Local Security Checks)",
                       "ssh/login/kernel_reporting_overwrite/enabled", "Report vulnerabilities of inactive Linux Kernel(s) separately",
                       "ssh/login/arch", "Machine hardware name (gathered via 'uname -m')",
                       "ssh/login/cpu_vendor_id", "CPU Vendor / Vendor ID (gathered via 'cat /proc/cpuinfo')",
                       "login/SSH/success", "Login via SSH successful",
                       "login/SSH/failed", "Login via SSH failed",
                       "ssh/no_linux_shell", "Login on a system without common commands like 'cat' or 'find'",
                       "ssh/locate/available", "locate: Command available",
                       "ssh/force/clear_buffer", "Clear received buffer before sending a command",
                       "ssh/force/nosh", "Don't prepend '/bin/sh -c' to used commands",
                       "ssh/force/nolang_sh", "Don't prepend 'LANG=C; LC_ALL=C;' to the '/bin/sh -c' commands",
                       "ssh/force/pty", "Commands are send via a pseudoterminal/pty",
                       "ssh/force/reconnect", "The SSH session/connection is re-opened before sending each command", # nb: Huawei VRP requires this
                       "ssh/send_extra_cmd", "Send an extra command",
                       "global_settings/ssh/debug", "Debugging enabled within 'Global variable settings'",
                       "ssh/lsc/enable_find", "Also use 'find' command to search for Applications enabled within 'Options for Local Security Checks'",
                       "ssh/lsc/descend_ofs", "Descend directories on other filesystem enabled within 'Options for Local Security Checks'",
                       "ssh/lsc/use_su", "Use 'su - USER' option on SSH commands",
                       "ssh/lsc/su_user", "Use this user for 'su - USER' option on SSH commands",
                       "ssh/lsc/find_timeout", "Amount of timeouts the 'find' command has reached",
                       "ssh/lsc/find_maxdepth", "Integer that sets the directory depth when using 'find' on unixoide systems",
                       "ssh/lsc/search_exclude_paths", "Folder exclusion regex for file search on Unixoide targets",
                       "ssh/cisco/broken_autocommand", "Misconfigured CISCO device. No autocommand should be configured for the scanning user.",
                       "ssh/restricted_shell", "Login on a system with a restricted shell" );

foreach kb_item( keys( kb_array ) ) {
  if( kb = get_kb_item( kb_item ) ) {

    # Special handling as a timeout of 1 would also evaluate to TRUE
    if( kb == TRUE && kb_item != "ssh/lsc/find_timeout" )
      kb = "TRUE";

    if( kb_item == "ssh/send_extra_cmd" )
      kb = str_replace( string:kb, find:'\n', replace:"\newline" );

    if( kb_item == "ssh/login/failed_rpm_db_access" ) {
      reason = get_kb_item( "ssh/login/failed_rpm_db_access/reason" );
      if( strlen( reason ) <= 0 ) reason = "No / empty response";
      info_array["rpm: Response to 'rpm' command (ssh/login/failed_rpm_db_access/reason)"] = reason;
    }

    if( kb_item == "ssh/lsc/find_timeout" && kb >= 3 ) {
      info_array[kb_array[kb_item] + ". To try to workaround this 'ssh/lsc/descend_ofs' was automatically set to 'no'. (" + kb_item + ")"] = kb;
    } else {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = kb;
    }
  } else {
    if( kb_item == "ssh/login/release" ) {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "None/Empty";
    } else if( kb_item == "ssh/lsc/find_timeout" ) {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "None";
    } else if( kb_item =~ "ssh/login/(freebsd|openbsd|osx|sol)" ) {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "Not applicable for target";
    } else {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "FALSE";
      if( kb_item == "ssh/locate/available" ) {
        locate_broken = TRUE;
        reason = get_kb_item( "ssh/locate/broken" );
        if( strlen( reason ) <= 0 )
          reason = "Empty/no response (maybe the database is not initialized or locate is not installed)";
        info_array["locate: Response to 'locate -S' command (ssh/locate/broken)"] = reason;
      }
    }
  }
}

info_array["Port used for authenticated scans (kb_ssh_transport())"] = kb_ssh_transport() + "/tcp";
info_array["User used for authenticated scans (kb_ssh_login())"] = kb_ssh_login();

# New SSH elevate privileges function
if( su_user = ssh_kb_privlogin() ) {
  info_array["Elevate Privileges Feature: Enabled"] = "TRUE";
  if( get_kb_item( "login/SSH/priv/failed" ) )
    info_array["Elevate Privileges Feature: Working"] = "FALSE";
  else
    info_array["Elevate Privileges Feature: Working"] = "TRUE";
  info_array["Elevate Privileges Feature: 'su' User used for authenticated scans (ssh_kb_privlogin())"] = su_user;
} else {
  info_array["Elevate Privileges Feature: Enabled"] = "FALSE";
}

report = text_format_table( array:info_array, columnheader:make_list( "Description (Knowledge base entry)", "Value/Content" ) );
if( locate_broken ) {
  report += '\n\nNOTE: The locate command seems to be unavailable for this user/account/system. This command ';
  report += "is highly recommended for authenticated scans to improve the search performance on the target system. ";
  report += "Please see the output above for a possible hint / reason why this command is not available.";
}

if( get_kb_item( "login/SSH/failed" ) ) {
  if( reason = get_kb_item( "login/SSH/failed/reason" ) )
    report += '\n\n' + reason;
}

error_list = get_kb_list( "ssh/login/broken_binaries" );
if( error_list && is_array( error_list ) ) {

  info_array = make_array();

  # Sort to not report changes on delta reports if just the order is different
  error_list = sort( error_list );
  foreach error( error_list ) {

    split = split( error, sep:"##----##----##", keep:FALSE );
    if( max_index( split ) != 2 )
      continue;

    cmd = split[0];
    msg = split[1];

    found = TRUE;
    info_array[cmd] = msg;
  }

  if( found ) {
    maxentries = 20;
    report += '\n\nThe following not working / broken binaries (list limited to ' + maxentries + ' entries) have been found during authenticated scans. The detection of products / software might be decreased.\n\n';
    report += text_format_table( array:info_array, maxentries:maxentries, columnheader:make_list( "Used command", "Message" ) );
  }
}

log_message( port:0, data:report );
exit( 0 );
