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

CPE = "cpe:/o:watchguard:fireware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106641");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-03-13 13:02:48 +0700 (Mon, 13 Mar 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:40:00 +0000 (Wed, 07 Sep 2022)");

  script_cve_id("CVE-2016-5387", "CVE-2016-5388", "CVE-2016-5386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WatchGuard Fireware XTM < 11.12.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_watchguard_firebox_consolidation.nasl");
  script_mandatory_keys("watchguard/firebox/detected");

  script_tag(name:"summary", value:"WatchGuard Fireware XMT Web UI is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-site request forgery (CSRF) on the Fireware Web UI login page

  - CVE-2016-5387, CVE-2106-5388, CVE-2016-5386: Multiple vulnerabilities in the lighttpd component
  used by Fireware

  - Vulnerability in the Fireware Web UI that could allow an attacker to enumerate management user
  login IDs");

  script_tag(name:"affected", value:"WatchGuard Fireware XTM prior to version 11.12.1.");

  script_tag(name:"solution", value:"Update to version 11.12.1 or later.");

  script_xref(name:"URL", value:"https://www.watchguard.com/support/release-notes/fireware/11/en-US/EN_ReleaseNotes_Fireware_11_12_1/index.html#Fireware/en-US/resolved_issues.html%3FTocPath%3D_____13");
  script_xref(name:"URL", value:"https://www.korelogic.com/Resources/Advisories/KL-001-2017-004.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "11.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.12.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
