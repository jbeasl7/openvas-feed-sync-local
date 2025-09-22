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

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142632");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2019-07-19 08:04:35 +0000 (Fri, 19 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-26 20:18:00 +0000 (Tue, 26 Apr 2022)");

  script_cve_id("CVE-2019-12525");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Security Update Advisory SQUID-2018:3");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service vulnerability due to incorrect buffer
  management when processing HTTP Digest Authentication credentials.");

  script_tag(name:"insight", value:"Due to incorrect input validation the HTTP Request header parser for Digest
  authentication may access memory outside the allocated memory buffer.

  On systems with memory access protections this can result in the Squid process being terminated unexpectedly.
  Resulting in a denial of service for all clients using the proxy.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid versions 3.3.9 - 3.5.28 and 4.x - 4.7.");

  script_tag(name:"solution", value:"Update to version 4.8 or later.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_3.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.3.9", test_version2: "3.5.28") ||
    version_in_range(version: version, test_version: "4.0", test_version2: "4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
