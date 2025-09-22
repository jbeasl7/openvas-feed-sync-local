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

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106615");
  script_version("2022-03-15T08:15:23+0000");
  script_tag(name:"last_modification", value:"2022-03-15 08:15:23 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2017-02-20 13:33:44 +0700 (Mon, 20 Feb 2017)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-22 18:26:00 +0000 (Wed, 22 Feb 2017)");

  script_cve_id("CVE-2016-7111");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT < 1.3.1, 2.x < 2.0.0-beta.2 Weak Content Security Policy Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MantisBT is prone to a weak Content Security Policy vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MantisBT uses a weak Content Security Policy when using the Gravatar plugin,
which allows remote attackers to conduct cross-site scripting (XSS) attacks via unspecified vectors.");

  script_tag(name:"affected", value:"MantisBT versions prior to 1.3.1 and 2.x prior to 2.0.0-beta.2.");

  script_tag(name:"solution", value:"Update to version 2.0.0-beta.2, 1.3.1 or later.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=21263");

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

if (version_is_less(version: version, test_version: "1.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^2\.0\.0") {
  if (version_is_less(version: version, test_version: "2.0.0-beta2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0-beta2", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
