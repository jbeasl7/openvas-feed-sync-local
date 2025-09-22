# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:jared_meeker:event_horizon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902088");
  script_version("2022-02-21T10:29:31+0000");
  script_tag(name:"last_modification", value:"2022-02-21 10:29:31 +0000 (Mon, 21 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2854", "CVE-2010-2855");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Event Horizon < 1.1.11 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_event_horizon_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("event_horizon/http/detected");

  script_tag(name:"summary", value:"Event Horizon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to the improper validation of user supplied
  data to 'YourEmail' and 'VerificationNumber' parameters to 'modfile.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code and manipulate SQL queries by injecting arbitrary SQL code in a
  user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Event Horizon version 1.1.10 and prior.");

  script_tag(name:"solution", value:"Update to version 1.1.11 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40517");

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

url = dir + '/modfile.php?YourEmail=<script>alert("VT-XSS-Testing")</script>';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && '<script>alert("VT-XSS-Testing")</script>' >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
