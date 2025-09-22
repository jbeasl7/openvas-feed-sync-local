# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103102");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CubeCart 2.0.6 XSS and SQLi Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516794");

  script_tag(name:"summary", value:"CubeCart is prone to an SQL injection (SQLi) and a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal cookie-
  based authentication credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"CubeCart 2.0.6 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

vtstrings = get_vt_strings();

if( dir == "/" )
  dir = "";

url = string( dir, '/sale_cat.php/"<script>alert(/', vtstrings["lowercase"], '-xss-test/)</script>' );

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/" + vtstrings["lowercase"] + "-xss-test/\)</script>", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
