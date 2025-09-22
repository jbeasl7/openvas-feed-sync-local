# Copyright (C) 2015 Greenbone Networks GmbHi
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

CPE = "cpe:/a:siemens:simatic_s7_1200";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105349");
  script_cve_id("CVE-2015-5698");
  script_version("2022-04-27T04:20:28+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Siemens SIMATIC S7-1200 CSRF Vulnerability (SSA-134003)");

  script_xref(name:"URL", value:"http://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-134003.pdf");

  script_tag(name:"last_modification", value:"2022-04-27 04:20:28 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-09-09 11:14:36 +0200 (Wed, 09 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_siemens_simatic_s7_consolidation.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected");

  script_tag(name:"summary", value:"Siemens SIMATIC S7-1200 devices are prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A successful exploit of this vulnerability could allow a remote
  attacker to perform actions with the permissions of a valid user.");

  script_tag(name:"insight", value:"The integrated web server of the affected programmable logic
  controllers (PLCs) could allow remote attackers to perform actions with the permissions of a
  victim user, provided the victim user has an active session and is induced to trigger the
  malicious request.");

  script_tag(name:"affected", value:"SIMATIC S7-1200 CPU family: All versions prior to V4.1.3.");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:version, test_version:"4.1.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.1.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
