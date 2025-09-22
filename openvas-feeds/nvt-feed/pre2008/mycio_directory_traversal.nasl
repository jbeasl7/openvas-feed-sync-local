# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10706");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3020");
  script_cve_id("CVE-2001-1144");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("McAfee myCIO Directory Traversal");
  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_dependencies("mycio_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 6515);
  script_mandatory_keys("mycio/installed");

  script_tag(name:"solution", value:"Configure your firewall to block access to this port (TCP 6515).
  Use the Auto Update feature of McAfee's myCIO to get the latest version.");

  script_tag(name:"summary", value:"The remote host runs McAfee's myCIO HTTP Server, which is vulnerable to Directory Traversal.");

  script_tag(name:"impact", value:"A security vulnerability in the product allows attackers to traverse outside the normal HTTP root
  path, and this exposes access to sensitive files.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:6515 );
if( ! get_kb_item( "mycio/" + port + "/installed" ) ) exit( 0 );

files = traversal_files( "windows" );
foreach file( keys( files ) ) {

  url = ".../.../.../.../" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
