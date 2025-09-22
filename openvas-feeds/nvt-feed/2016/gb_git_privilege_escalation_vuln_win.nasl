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

CPE = "cpe:/a:git_for_windows_project:git_for_windows";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809816");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-9274");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:37:00 +0000 (Thu, 13 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-11-22 11:18:59 +0530 (Tue, 22 Nov 2016)");
  script_name("Git < 2.0 Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"Git is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an untrusted search
  path vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow  local users to gain privileges via a Trojan horse
  git.exe file in the current working directory.");

  script_tag(name:"affected", value:"Git version prior to 2.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/git-for-windows/git/issues/944");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94289");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_git_detect_win.nasl");
  script_mandatory_keys("Git/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"2.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);