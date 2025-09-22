# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804609");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-3935");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-02 10:56:30 +0530 (Mon, 02 Jun 2014)");
  script_name("XOOPS Glossaire Module 'glossaire-aff.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67460");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126701");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/xoops-glossaire-10-sql-injection");

  script_tag(name:"summary", value:"XOOPS module Glossaire is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it
is possible to execute sql query.");
  script_tag(name:"insight", value:"The flaw is due to insufficient validation of 'lettre' HTTP GET parameter
passed to 'glossaire-aff.php' script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable
web application.");
  script_tag(name:"affected", value:"Glossaire Module version 1.0 for XOOPS");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/modules/glossaire/glossaire-aff.php?lettre=K'";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:">mysql_fetch_", extra_check:make_list("expects parameter", "xoopsGetElementById" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
