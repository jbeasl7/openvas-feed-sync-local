# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:qnap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106489");
  script_version("2022-05-30T10:35:56+0000");
  script_tag(name:"last_modification", value:"2022-05-30 10:35:56 +0000 (Mon, 30 May 2022)");
  script_tag(name:"creation_date", value:"2017-01-03 09:57:21 +0700 (Tue, 03 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP NAS Devices Heap Overflow Vulnerability (NAS-201701-06)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("qnap/nas/http/detected");

  script_tag(name:"summary", value:"QNAP NAS devices are prone to a heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"QNAP NAS devices suffer from a critical Heap Overflow in
  'cgi.cgi' and non critical stack crash in 'jc.cgi' and 'mediaGet.cgi'.");

  script_tag(name:"impact", value:"An unauthenticated attacker may gain root privileges.");

  script_tag(name:"solution", value:"Update to QTS 4.2.3 builds 20170121, 20170124 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40985");
  script_xref(name:"URL", value:"https://www.qnap.com/en-us/security-advisory/NAS-201701-06");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/cgi-bin/cgi.cgi?u=admin&p=" + crap(length: 264, data: "A");

if (http_vuln_check(port: port, url: url, pattern: "======= Memory map: ========", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
