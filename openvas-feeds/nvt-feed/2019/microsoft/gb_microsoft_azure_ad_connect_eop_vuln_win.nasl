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

CPE = "cpe:/a:microsoft:azure_ad_connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815079");
  script_version("2021-09-14T09:22:46+0000");
  script_cve_id("CVE-2019-1000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-14 09:22:46 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-05-17 12:30:03 +0530 (Fri, 17 May 2019)");
  script_name("Microsoft Azure AD Connect Elevation of Privilege Vulnerability - Windows");

  script_tag(name:"summary", value:"Microsoft Azure AD Connect is prone to an elevation of
  privilege vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a privilege escalation error in
  PowerShell cmdlets.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute two
  PowerShell cmdlets in context of a privileged account, and perform privileged actions.");

  script_tag(name:"affected", value:"Microsoft Azure Active Directory Connect build 1.3.20.0.");

  script_tag(name:"solution", value:"Update to version 1.3.21.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1000");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-upgrade-previous-version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_microsoft_azure_ad_connect_detect_win.nasl");
  script_mandatory_keys("microsoft/azureadconnect/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "1.3.20.0") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.21.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);