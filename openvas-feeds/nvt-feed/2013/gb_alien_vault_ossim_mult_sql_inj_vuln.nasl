# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:alienvault:open_source_security_information_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804028");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-5967");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-17 15:25:41 +0530 (Thu, 17 Oct 2013)");
  script_name("AlienVault OSSIM 'date_from' Parameter Multiple SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"AlienVault OSSIM is prone to multiple sql injection vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check whether it is able to execute sql query
  or not.");
  script_tag(name:"solution", value:"Upgrade to version 4.4.0 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitation of user-supplied input to the
  'date_form' parameter when displaying radar reports.");
  script_tag(name:"affected", value:"AlienVault Open Source Security Information Management (OSSIM) version 4.3
  and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62790");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_mandatory_keys("OSSIM/installed");
  script_require_ports("Services/www", 443);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.alienvault.com/open-threat-exchange/projects");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port) ) exit(0);

if( dir == "/" ) dir = "";

url = dir + "/RadarReport/radar-iso27001-potential.php?date_from='SQL-Injection-Test";

req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port:port, data:req );

if( res && res =~ "You have an error in your SQL syntax.*SQL-Injection-Test"
        && "datawarehouse.ssi_user" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
