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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112480");
  script_version("2021-09-29T12:07:39+0000");
  script_tag(name:"last_modification", value:"2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-01-08 11:36:11 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 13:29:00 +0000 (Wed, 01 Aug 2018)");

  script_cve_id("CVE-2018-12034", "CVE-2018-12035");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("YARA < 3.8.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_yara_ssh_detect.nasl");
  script_mandatory_keys("yara/detected");

  script_tag(name:"summary", value:"YARA is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Parsing a specially crafted compiled rule file can cause an out of bounds
  read vulnerability in yr_execute_code in libyara/exec.c.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"YARA through version 3.7.1.");

  script_tag(name:"solution", value:"Update to version 3.8.1.");

  script_xref(name:"URL", value:"https://bnbdr.github.io/posts/extracheese/");
  script_xref(name:"URL", value:"https://github.com/bnbdr/swisscheese/");
  script_xref(name:"URL", value:"https://github.com/VirusTotal/yara/issues/891");

  exit(0);
}

CPE = "cpe:/a:virustotal:yara";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version: vers, test_version: "3.8.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "3.8.1", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
