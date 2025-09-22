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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142325");
  script_version("2021-08-30T11:01:18+0000");
  script_tag(name:"last_modification", value:"2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-04-30 07:20:56 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 18:15:00 +0000 (Wed, 18 Dec 2019)");

  script_cve_id("CVE-2019-6468");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability (CVE-2019-6468) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ISC BIND Supported Preview Edition is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In BIND Supported Preview Edition, an error in the nxdomain-redirect feature
  can occur in versions which support EDNS Client Subnet (ECS) features. In those versions which have ECS support,
  enabling nxdomain-redirect is likely to lead to BIND exiting due to assertion failure.");

  script_tag(name:"impact", value:"If nxdomain-redirect is enabled (via configuration) in a vulnerable BIND
  release, a malicious party can cause BIND to exit by deliberately triggering the bug.");

  script_tag(name:"affected", value:"BIND Supported Preview Edition version 9.10.5-S1 to 9.11.5-S5.");

  script_tag(name:"solution", value:"Update to version 9.11.5-S6, 9.11.6-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2019-6468");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "^9\.(10|11)\.[0-9]s[0-9]") {
  if (version_in_range(version: version, test_version: "9.10.5s1", test_version2: "9.11.5s5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.5-S6/9.11.6-S1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
