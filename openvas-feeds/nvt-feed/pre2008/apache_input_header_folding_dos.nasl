# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12293");
  script_version("2024-08-02T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-08-02 05:05:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2004-0493", "CVE-2004-0748");
  script_xref(name:"OSVDB", value:"7269");
  script_name("Apache HTTP Server 2.x < 2.0.50 Multiple DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_xref(name:"URL", value:"http://www.guninski.com/httpd1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10619");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12877");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2004-0493: There is denial of service in apache httpd 2.0.x
  by sending a specially crafted HTTP request. It is possible to consume arbitrary amount of memory.
  On 64 bit systems with more than 4GB virtual memory this may lead to heap based buffer overflow.

  CVE-2004-0748: There is also a denial of service vulnerability in mod_ssl's ssl_io_filter_cleanup
  function. By sending a request to vulnerable server over SSL and closing the connection before the
  server can send a response, an attacker can cause a memory violation that crashes the server.");

  script_tag(name:"affected", value:"Apache HTTP Server versions 2.x prior to 2.0.50.");

  script_tag(name:"solution", value:"Update to version 2.0.50 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

if( concl = egrep( pattern:"^Server\s*:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-9][^0-9])([0-3][0-9][^0-9])|(4[0-9][^0-9]))", string:banner ) ) {
  concl = chomp( concl );
  report = report_fixed_ver( installed_version:concl, fixed_version:"2.0.50" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
