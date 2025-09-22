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

CPE = "cpe:/a:ibm:bigfix_remote_control";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106415");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-11-28 11:50:57 +0700 (Mon, 28 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-30 03:05:00 +0000 (Wed, 30 Nov 2016)");

  script_cve_id("CVE-2016-2927", "CVE-2016-2928", "CVE-2016-2929");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM BigFix Remote Control < 9.1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hcl_bigfix_remote_control_http_detect.nasl");
  script_mandatory_keys("hcl/bigfix/remote_control/detected");

  script_tag(name:"summary", value:"IBM BigFix Remote Control is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM BigFix Remote Control is prone to multiple vulnerabilities:

  - CVE-2016-2927: IBM BigFix Remote Control could allow a remote attacker to obtain sensitive
  information through man in the middle techniques due to using out of date encryption algorithms.

  - CVE-2016-2928: IBM BigFix Report Control could allow an authenticated attacker to obtain
  sensitive information from error logs.

  - CVE-2016-2929: IBM BigFix Remote Control uses a weak default password policy that could allow
  an attacker to easily guess user passwords.");

  script_tag(name:"impact", value:"A remote attacker may obtain sensitive information or could
  easily guess user passwords.");

  script_tag(name:"affected", value:"IBM BigFix Remote Control version 9.1.2 and prior.");

  script_tag(name:"solution", value:"Update to version 9.1.3 or later.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21991875");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21991951");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21991880");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
