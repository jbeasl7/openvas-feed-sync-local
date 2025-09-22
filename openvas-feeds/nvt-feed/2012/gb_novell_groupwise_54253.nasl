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

CPE = "cpe:/a:microfocus:groupwise";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103519");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-07-16 12:02:03 +0200 (Mon, 16 Jul 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-0410");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell Groupwise 8.0 - 8.02 HP3 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_microfocus_groupwise_consolidation.nasl");
  script_mandatory_keys("microfocus/groupwise/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Groupwise is prone to a directory traversal vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Remote attackers can use specially crafted requests with
  directory traversal sequences ('../') to retrieve arbitrary files in the context of the
  application.

  Exploiting this issue may allow an attacker to obtain sensitive information that could aid in
  further attacks.");

  script_tag(name:"affected", value:"Groupwise version 8.0x through 8.02 HP3.");

  script_tag(name:"solution", value:"See the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54253");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/webacc?User.interface=/../webacc/wml";

if (http_vuln_check(port: port, url: url, pattern: "<wml>",
                    extra_check: make_list("<template>", "Novell GroupWise", "<onevent"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
