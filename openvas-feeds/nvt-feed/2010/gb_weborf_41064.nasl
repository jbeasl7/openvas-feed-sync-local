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

CPE = "cpe:/a:salvo_tomaselli:weborf_http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100691");
  script_version("2022-04-12T08:46:17+0000");
  script_tag(name:"last_modification", value:"2022-04-12 08:46:17 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2010-06-23 16:49:06 +0200 (Wed, 23 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-2435");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Weborf < 0.12.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_weborf_http_detect.nasl");
  script_mandatory_keys("weborf/detected");

  script_tag(name:"summary", value:"Weborf is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the application
  to crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Weborf version 0.12.1 and probably prior.");

  script_tag(name:"solution", value:"Update to version 0.12.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41064");
  script_xref(name:"URL", value:"http://freshmeat.net/projects/weborf/releases/318531");
  script_xref(name:"URL", value:"http://code.google.com/p/weborf/source/browse/branches/0.12.2/CHANGELOG?spec=svn437&r=437");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.12.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
