# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuralstorm:nuralstorm_webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100743");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-08-04 13:50:35 +0200 (Wed, 04 Aug 2010)");
  script_name("NuralStorm Webmail Multiple Security Vulnerabilities");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_nuralstorm_webmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nuralstorm_webmail/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41559");
  script_xref(name:"URL", value:"http://www.nuralstorm.net/");
  script_xref(name:"URL", value:"http://www.madirish.net/?article=466");

  script_tag(name:"summary", value:"NuralStorm Webmail is prone to multiple security vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain potentially
  sensitive information, create or delete arbitrary files, send unsolicited bulk email to users, execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site,
  steal cookie-based authentication credentials, perform unauthorized actions, disclose or modify sensitive
  information, or upload arbitrary code and run it in the context of the webserver process. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"Webmail 0.985b is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = string(dir, "/book_include.php?USE_ADDRESS_BOOK=1&ADDRESS_BOOK_MESSAGE=1&BGCOLOR1=%22%3E%3Cscript%3Ealert(%27vt-xss-test%27);%3C/script%3E%3C%22");
if(http_vuln_check(port:port,url:url,pattern:"<script>alert\('vt-xss-test'\);</script>",extra_check:"selectedIndex", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
