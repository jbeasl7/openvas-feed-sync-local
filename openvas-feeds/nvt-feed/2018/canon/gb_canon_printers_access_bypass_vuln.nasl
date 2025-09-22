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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813416");
  script_version("2022-04-14T12:29:20+0000");
  script_tag(name:"last_modification", value:"2022-04-14 12:29:20 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2018-06-05 11:37:19 +0530 (Tue, 05 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:08:00 +0000 (Wed, 01 Aug 2018)");

  script_cve_id("CVE-2018-11711");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Canon MF210/MF220 Series Printers Access Bypass Vulnerability (Apr 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Canon MF210/MF220 Series Printers are prone to an access bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient access restrictions at any
  URL of the device that requires authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  the authentication without a PIN at any URL of the device that requires authentication.");

  script_tag(name:"affected", value:"Canon MF210 and MF220 Series.");

  script_tag(name:"solution", value:"The vendor reportedly responded that this issue occurs when a
  customer keeps the default settings without using the countermeasures and best practices shown in
  the documentation.");

  script_xref(name:"URL", value:"https://gist.github.com/huykha/9dbcd0e46058f1e18bab241d1b2754bd");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

cpe_list = make_list("cpe:/h:canon:mf220",
                     "cpe:/h:canon:mf210");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

req = http_post_put_req(port: port, url: "/tryLogin.cgi", data: "loginM=&0000=0010&0001=&0002=",
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 303" && "Location:" >< res && "Set-Cookie" >< res) {
  cookie = eregmatch(pattern: "Set-Cookie: (fusion-http-session-id=([0-9a-zA-Z]+));", string: res);
  cookie = cookie[1];
}

if(!cookie)
  exit(0);

url =  "/portal_top.html";
req = http_get_req(port: port, url: url, add_headers: make_array("Cookie", cookie));
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && ">Log Out<" >< res && ">Copyright CANON INC" >< res &&
    ">Address Book<" >< res && ">Cartridge Information<" >< res && ">Device Status<" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
