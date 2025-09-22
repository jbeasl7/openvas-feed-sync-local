# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810000");
  script_version("2024-05-08T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-08 05:05:32 +0000 (Wed, 08 May 2024)");
  script_tag(name:"creation_date", value:"2009-08-17 09:05:44 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Availability of scanner helper tools");
  script_category(ACT_INIT);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");

  script_add_preference(name:"Silent tool check", type:"checkbox", value:"yes", id:1);
  #TBD: Set the default of Silent tool check above to "no" once GOS 3.1 has been deprecated? The executed_on_gos below is working on GOS 4.2+.
  script_add_preference(name:"Silent tool check on Greenbone OS (GOS)", type:"checkbox", value:"yes", id:2);

  script_tag(name:"summary", value:"This routine checks for the presence of various tools that
  support the scan engine. If some tools are not accessible for the scan engine, one or more VTs
  could not be executed properly.

  The consequence might be that certain vulnerabilities or additional (compliance) tests are missed
  because respective tests are not performed.

  Note: The tool check is always 'silent' by default when running on a Greenbone OS (GOS) based
  installation like the Greenbone Security Manager (GSM) or Greenbone Enterprise TRIAL. Both
  installation are shipping all required / supported tools by default.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");

silent_check = script_get_preference("Silent tool check", id:1);
silent_gos   = script_get_preference("Silent tool check on Greenbone OS (GOS)", id:2);
is_gos       = executed_on_gos();

# nb: See Note in the description.
if(is_gos && silent_gos == "yes")
  silent_check = "yes";

all_tools_available = TRUE;

# (built-in) WMI support
if(wmi_versioninfo()) {
  set_kb_item(name:"Tools/Present/wmi", value:TRUE);
} else {
  tools_summary += '\n\nTool:   WMI Client (Scanner not build with extended WMI support via the openvas-smb module)\n';
  tools_summary += 'Effect: Any VTs that do rely on the built-in WMI functionality will not be executed. Most likely reduced are Authenticated Scans due to missing ';
  tools_summary += 'Local Security Checks (LSC), compliance tests and OVAL VTs.\n';
  tools_summary += 'Note:   If you did not provide SMB credentials or do not scan host with Windows operating systems, the absence will not reduce the number of executed VTs.';
  set_kb_item(name:"Tools/Missing/wmi", value:TRUE);
  all_tools_available = FALSE;
}

# (built-in) SMB support
if(smb_versioninfo()) {
  set_kb_item(name:"Tools/Present/smb", value:TRUE);
} else {
  tools_summary += '\n\nTool:   SMB Client (Scanner not build with extended WMI support via the openvas-smb module)\n';
  tools_summary += 'Effect: Any VTs that do rely on the built-in SMB functionality will not be executed. Most likely reduced are Authenticated Scans due to missing ';
  tools_summary += 'Local Security Checks (LSC), compliance tests and OVAL VTs.\n';
  tools_summary += 'Note:   If you did not provide SMB credentials or do not scan host with Windows operating systems, the absence will not reduce the number of executed VTs.';
  set_kb_item(name:"Tools/Missing/smb", value:TRUE);
  all_tools_available = FALSE;
}

# Scanner needs to be build against libsnmp or have snmpget installed for extended SNMP
# functionality in e.g. snmp_func.inc.
# nb: This functions should be always there since openvas-scanner version 20.08.1 / via:
# https://github.com/greenbone/openvas-scanner/pull/594
if(defined_func("snmpv3_get")) {
  set_kb_item(name:"Tools/Present/libsnmp", value:TRUE);
} else {
  tools_summary += '\n\nTool:   SNMP Client (Scanner not build with libsnmp support)\n';
  tools_summary += 'Effect: Advanced SNMP checks and connections to SNMPv3 only services will fail.\n';
  tools_summary += 'Note:   If you do not scan the host with SNMP services, the absence will not reduce the number of executed VTs.';
  set_kb_item(name:"Tools/Missing/libsnmp", value:TRUE);
  all_tools_available = FALSE;
}

sufficient_nmap_found = FALSE;
if(find_in_path("nmap")) {
  nmap_v_out = pread(cmd:"nmap", argv:make_list("nmap", "-V"));
  if(nmap_v_out) {
    ver = ereg_replace(pattern:".*nmap version ([0-9.]+).*", string:nmap_v_out, replace:"\1", icase:TRUE);
    if(ver == nmap_v_out)
      ver = NULL;
  }

  if(ver =~ "^[4-9]\.") {
    sufficient_nmap_found = TRUE;
  }
}

if(sufficient_nmap_found == TRUE) {
  set_kb_item(name:"Tools/Present/nmap", value:TRUE);
} else {
  tools_summary += '\n\nTool:   nmap 4.0 or newer\n';
  tools_summary += 'Effect: Port scanning and service detection based on nmap is not available.';
  set_kb_item(name:"Tools/Missing/nmap", value:TRUE);
  all_tools_available = FALSE;
}

# 2008/pnscan.nasl
if(find_in_path("pnscan")) {
  set_kb_item(name:"Tools/Present/pnscan", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/pnscan", value:TRUE);
  tools_summary += '\n\nTool:   pnscan\n';
  tools_summary += 'Effect: Optional port scanning based on pnscan is not available.';
  all_tools_available = FALSE;
}

# pre2008/snmpwalk_portscan.nasl
if(find_in_path("snmpwalk")) {
  set_kb_item(name:"Tools/Present/snmpwalk", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/snmpwalk", value:TRUE);
  tools_summary += '\n\nTool:   snmpwalk\n';
  tools_summary += 'Effect: Optional port scanning based on snmpwalk is not available.';
  all_tools_available = FALSE;
}

# pre2008/ldapsearch.nasl
if(find_in_path("ldapsearch")) {
  set_kb_item(name:"Tools/Present/ldapsearch", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/ldapsearch", value:TRUE);
  tools_summary += '\n\nTool:   ldapsearch\n';
  tools_summary += 'Effect: Advanced LDAP directory checks are not available.';
  all_tools_available = FALSE;
}

# sw_ssl_tls_cert_get_hostname.nasl
ping = find_in_path("ping");
ping6 = find_in_path("ping6");
if(ping || ping6) {

  set_kb_item(name:"Tools/Present/ping", value:TRUE);

  # nb: There are differences between inetutils and iputils packages and versions.
  # Some packages have e.g. a ping6 binary, others just a symlink from ping6 to ping.
  #
  # First check if the ping command supports the -6/-4 parameter
  check = pread(cmd:"ping", argv:make_list("ping", "--usage"), cd:TRUE);
  if("Usage: ping" >< check && "64]" >< check)
    param64 = TRUE;

  if(TARGET_IS_IPV6()) {
    # If the -6 parameter is available explicitly specify it for the ping command and use only "ping"
    if(param64){
      ping_cmd = "ping";
      set_kb_item(name:"Tools/Present/ping/extra_cmd", value:"-6");
    } else {
      if(ping6)
        ping_cmd = "ping6";
      else
        ping_cmd = "ping";
    }
    set_kb_item(name:"Tools/Present/ping/bin", value:ping_cmd);
  } else {
    # If the -4 parameter is available explicitly specify it for the ping command
    if(param64)
      set_kb_item(name:"Tools/Present/ping/extra_cmd", value:"-4");
    else
      ping_cmd = "ping";
    set_kb_item(name:"Tools/Present/ping/bin", value:"ping");
  }
} else {
  set_kb_item(name:"Tools/Missing/ping", value:TRUE);
  tools_summary += '\n\nTool:   ping/ping6\n';
  tools_summary += 'Effect: Various VTs are currently relying on the availability of the \'ping\' command.';
  all_tools_available = FALSE;
}

# Various
if(find_in_path("openssl")) {
  set_kb_item(name:"Tools/Present/openssl", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/openssl", value:TRUE);
  tools_summary += '\n\nTool:   openssl\n';
  tools_summary += 'Effect: Various VTs of the \'IT-Grundschutz\' family currently rely on the availability of the \'openssl\' command.';
  all_tools_available = FALSE;
}

# GSHB/GSHB_Printer_SSL-TLS.nasl
if(find_in_path("sed")) {
  set_kb_item(name:"Tools/Present/sed", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/sed", value:TRUE);
  tools_summary += '\n\nTool:   sed\n';
  tools_summary += 'Effect: The VT \'Printer Test SSL/TLS\' (OID: 1.3.6.1.4.1.25623.1.0.96056) is currently relying on the availability of the \'sed\' command.';
  all_tools_available = FALSE;
}

# 2009/remote-net-hub-3com.nasl
if(find_in_path("macof")) {
  set_kb_item(name:"Tools/Present/macof", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/macof", value:TRUE);
  tools_summary += '\n\nTool:   macof\n';
  tools_summary += 'Effect: The VT \'3com switch2hub\' (OID: 1.3.6.1.4.1.25623.1.0.80103) is currently relying on the availability of the \'macof\' command.';
  all_tools_available = FALSE;
}

# pre2008/netstat_portscan.nasl
if(find_in_path("netstat")) {
  set_kb_item(name:"Tools/Present/netstat", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/netstat", value:TRUE);
  tools_summary += '\n\nTool:   netstat\n';
  tools_summary += 'Effect: Optional port scanning based on netstat when scanning the localhost is not available.';
  all_tools_available = FALSE;
}

# 2012/gb_rugged_operating_system_53215.nasl and GSHB/EL15/GSHB_M4_017.nasl
if(find_in_path("perl")) {
  set_kb_item(name:"Tools/Present/perl", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/perl", value:TRUE);
  tools_summary += '\n\nTool:   perl\n';
  tools_summary += 'Effect: Various VTs are currently relying on the availability of the \'perl\' command.';
  all_tools_available = FALSE;
}

# Send final summary as log information if "Silent tool check" is not "yes"
if(silent_check == "yes")
  exit(0);

if(all_tools_available == FALSE) {
  report  = "The following tools are not accessible for the scan engine. Please contact the responsible administrator of the ";
  report += 'installation to make the missing tool(s) available.';
  report += tools_summary;
} else {
  report = "All checks for presence of scanner tools were successful. This means they are found and are sufficiently up-to-date.";
}

log_message(port:0, data:report);
exit(0);
