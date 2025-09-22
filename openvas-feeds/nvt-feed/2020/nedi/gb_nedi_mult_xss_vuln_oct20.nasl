# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:nedi:nedi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144886");
  script_version("2021-08-17T06:00:55+0000");
  script_tag(name:"last_modification", value:"2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-11-04 07:58:28 +0000 (Wed, 04 Nov 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-03 15:41:00 +0000 (Tue, 03 Nov 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-23868", "CVE-2020-23989");

  script_name("NeDi <= 1.9C Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nedi_detect.nasl");
  script_mandatory_keys("nedi/detected");

  script_tag(name:"summary", value:"NeDi is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting vulnerabilities exist in pwsec.php and inc/rt-popup.php.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"NeDi version 1.9C and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.9C Patch1 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/harsh-bothra/f4285d20a7718d2e1934c042b04d9fac");
  script_xref(name:"URL", value:"https://gist.github.com/harsh-bothra/d8c86b8279b23ff6d371f832ba0a5b6b");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.9.100")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9C Patch1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
