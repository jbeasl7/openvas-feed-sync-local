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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806856");
  script_version("2022-06-01T10:19:27+0000");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-01 10:19:27 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2016-02-08 18:19:08 +0530 (Mon, 08 Feb 2016)");

  script_cve_id("CVE-2013-4505");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Subversion DoS Vulnerability (Feb 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_subversion_detect.nasl");
  script_mandatory_keys("apache/subversion/detected");

  script_tag(name:"summary", value:"Apache Subversion is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the 'is_this_legal()' function in
  mod_dontdothat does not restrict requests from serf based clients.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause a
  denial of service or bypass intended access restriction.");

  script_tag(name:"affected", value:"Apache Subversion version 1.4.0 through 1.7.13 and 1.8.0
  through 1.8.4.");

  script_tag(name:"solution", value:"Update to version 1.7.14, 1.8.5 or later.");

  script_xref(name:"URL", value:"https://subversion.apache.org/security/CVE-2013-4505-advisory.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63966");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "1.8.0", test_version_up: "1.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.4.0", test_version2: "1.7.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.14");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
