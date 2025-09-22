# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103604");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-11-06 13:03:17 +0100 (Tue, 06 Nov 2012)");
  script_name("Symphony Multiple Remote Security Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symphony/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56094");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed. However, Symantec has not confirmed
  this. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Symphony is prone to multiple remote security
  vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An authentication bypass vulnerability

  - Multiple cross-site scripting (XSS) vulnerabilities

  - An HTML injection vulnerability

  - Multiple SQL injection (SQLi) vulnerabilities");

  script_tag(name:"impact", value:"An attacker may leverage these issues to run malicious HTML and script
  codes in the context of the affected browser, steal cookie-based
  authentication credentials, to gain unauthorized access to the
  affected application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Symphony 2.3 is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

host = http_host_name( port:port );

if( dir == "/" ) dir = "";
url = dir + "/login/retrieve-password/";

req = string("POST ", url," HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "Connection: keep-alive\r\n",
             "Referer: http://",host, dir,"/login/retrieve-password/\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 101\r\n",
             "\r\n",
             "email=%22%3E%3Cscript%3Ealert%28%27xss-test%27%29%3C%2Fscript%3E&action%5Breset%5D=Send+Email\r\n");
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( result !~ "^HTTP/1\.[01] 200" ) exit( 0 );

if( "<script>alert('xss-test')</script>" >< result && "Send Email" >< result ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit(99);
