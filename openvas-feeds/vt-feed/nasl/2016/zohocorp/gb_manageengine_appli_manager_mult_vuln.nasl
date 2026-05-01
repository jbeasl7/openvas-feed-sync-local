# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_applications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808053");
  script_version("2026-04-23T06:21:05+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2026-04-23 06:21:05 +0000 (Thu, 23 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-05-23 11:29:35 +0530 (Mon, 23 May 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ManageEngine Applications Manager < 12710 Multiple Vulnerabilities - Active Check");

  script_tag(name:"summary", value:"ManageEngine Applications Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain maintenance schedule.");

  script_tag(name:"insight", value:"Multiple flwas are due to:

  - An improper validation of authentication for some scripts.

  - The downTimeScheduler.do script is vulnerable to a Boolean based blind.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to complete unauthorized access to the back-end database, to allow
  public access to sensitive data.");

  script_tag(name:"affected", value:"ManageEngine Applications Manager
  Build No 12700.");

  script_tag(name:"solution", value:"Apply Vendor supplied patch build 12710.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/May/20");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_appli_manager_http_detect.nasl");
  script_require_ports("Services/www", 9090);
  script_mandatory_keys("manageengine/applications_manager/http/detected");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/applications_manager/release-notes.html");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/downTimeScheduler.do?method=maintenanceTaskListView&tabtoLoad=downtimeSchedulersDiv";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"Schedule Name",
                     extra_check:make_list( "Status", "Occurrence", "Zoho Corp" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
