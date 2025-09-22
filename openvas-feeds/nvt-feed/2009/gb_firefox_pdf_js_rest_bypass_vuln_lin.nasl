# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900351");
  script_version("2022-03-01T14:58:37+0000");
  script_tag(name:"last_modification", value:"2022-03-01 14:58:37 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1597");
  script_name("Mozilla Firefox PDF JavaScript Restriction Bypass Vulnerability - Linux");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503183/100/0/threaded");
  script_xref(name:"URL", value:"http://secniche.org/papers/SNS_09_03_PDF_Silent_Form_Re_Purp_Attack.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation will let attacker execute arbitrary codes in the
  context of the malicious PDF file and execute arbitrary codes into the context
  of the remote system.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0.10 and prior.");
  script_tag(name:"insight", value:"Error while executing DOM calls in response to a javascript: URI in the target
  attribute of a submit element within a form contained in an inline PDF file
  which causes bypassing restricted Adobe's JavaScript restrictions.");
  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a PDF JavaScript restriction bypass vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version:"3.0.10")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
