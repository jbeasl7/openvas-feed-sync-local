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

CPE = "cpe:/h:verizon:fios_router";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142241");
  script_version("2023-10-27T16:11:33+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-04-11 06:09:41 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-3914", "CVE-2019-3915", "CVE-2019-3916");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Verizon Fios Quantum Gateway Router < 02.02.00.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_verizon_fios_router_detect.nasl");
  script_mandatory_keys("verizon/fios_router/detected");

  script_tag(name:"summary", value:"Verizon Fios Quantum Gateway Router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Verizon Fios Quantum Gateway Router is prone to multiple vulnerabilities:

  - Authenticated Remote Command Injection (CVE-2019-3914)

  - Login Replay (CVE-2019-3915)

  - Password Salt Disclosure (CVE-2019-3916)");

  script_tag(name:"affected", value:"Verizon Fios Quantum Gateway Router prior to firmware version 02.02.00.13.");

  script_tag(name:"solution", value:"Update to firmware version 02.02.00.13 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/blog/verizon-fios-quantum-gateway-routers-patched-for-multiple-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

url = "/api";

if (http_vuln_check(port: port, url: url, pattern: '"passwordSalt":"[a-f0-9-]+"')) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
