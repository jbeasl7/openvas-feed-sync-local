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

CPE = "cpe:/a:tableau:tableau_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114164");
  script_version("2022-09-02T10:10:40+0000");
  script_tag(name:"last_modification", value:"2022-09-02 10:10:40 +0000 (Fri, 02 Sep 2022)");
  script_tag(name:"creation_date", value:"2019-12-13 16:06:07 +0100 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-12 20:07:00 +0000 (Thu, 12 Dec 2019)");

  script_cve_id("CVE-2019-19719");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tableau Server XSS Vulnerability (ADV-2019-047)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_tableau_server_http_detect.nasl");
  script_mandatory_keys("tableau_server/detected");

  script_xref(name:"URL", value:"https://community.tableau.com/s/news/a0A4T000001v3TIUAY/important-adv2019047-open-redirect-on-embeddedauthredirect-page");

  script_tag(name:"summary", value:"Tableau Server is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tableau Server on Windows and Linux allows XSS via the
  embeddedAuthRedirect page. The server fails to properly validate the path that is presented on
  this redirect page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to initiate a
  reflected cross-site scripting operation via JavaScript, which runs in the client context.
  Alternatively, a Tableau server user who clicks on a malicious link could be redirected to an
  attacker-controlled location.");

  script_tag(name:"affected", value:"Tableau Server versions 10.3 through 2019.4.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

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

if (version_in_range(version: version, test_version: "10.3", test_version2: "10.4.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5", test_version2: "10.5.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2018.1", test_version2: "2018.1.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2018.1.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2018.2", test_version2: "2018.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2018.2.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2018.3", test_version2: "2018.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2018.3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2019.1", test_version2: "2019.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2019.1.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2019.2", test_version2: "2019.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2019.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2019.3", test_version2: "2019.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2019.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "2019.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2019.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
