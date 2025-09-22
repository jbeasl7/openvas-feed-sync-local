# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/o:sophos:sfos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106477");
  script_version("2022-03-30T12:11:10+0000");
  script_tag(name:"last_modification", value:"2022-03-30 12:11:10 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-12-16 17:02:59 +0700 (Fri, 16 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2016-5696");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos XG Firewall < 16.01.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sophos_xg_consolidation.nasl");
  script_mandatory_keys("sophos/xg_firewall/detected");

  script_tag(name:"summary", value:"Sophos XG Firewall is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sophos XG Firewall is prone to multiple vulnerabilities:

  - CVE-2016-5696: Linux Kernel vulnerability

  - No CVE: SQL Injection (SQLi) vulnerability in User Portal");

  script_tag(name:"affected", value:"Sophos XG Firewall prior to version 16.01.0.");

  script_tag(name:"solution", value:"Update to version 16.01.0 or later.");

  script_xref(name:"URL", value:"https://community.sophos.com/products/xg-firewall/b/xg-blog/posts/sfos-16-01-0-released-1523397409");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-16-671/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "16.01.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.01.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
