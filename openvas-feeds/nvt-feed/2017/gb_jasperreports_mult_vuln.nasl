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

CPE = "cpe:/a:tibco:jasperreports_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106923");
  script_version("2022-03-17T02:50:34+0000");
  script_tag(name:"last_modification", value:"2022-03-17 02:50:34 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2017-07-05 13:59:32 +0700 (Wed, 05 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 12:41:00 +0000 (Thu, 09 Sep 2021)");

  script_cve_id("CVE-2017-5528", "CVE-2017-5529");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TIBCO JasperReports < 6.4.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tibco_jasperreports_http_detect.nasl");
  script_mandatory_keys("tibco/jasperreports/detected");

  script_tag(name:"summary", value:"TIBCO JasperReports is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TIBCO JasperReports is prone to multiple vulnerabilities:

  - Cross-site scripting (XSS) and cross-site request forgery (CSRF) vulnerabilities
  (CVE-2017-5528)

  - Information disclosure vulnerability (CVE-2017-5529)");

  script_tag(name:"affected", value:"TIBCO JasperReports Server 6.1.1 and prior, version 6.2.x
  through 6.2.1 and 6.3.0.");

  script_tag(name:"solution", value:"Update to version 6.1.2, 6.2.3, 6.3.2 or later.");

  script_xref(name:"URL", value:"https://www.tibco.com/support/advisories/2017/06/tibco-security-advisory-june-28-2017-tibco-jasperreports-server-2017");
  script_xref(name:"URL", value:"https://www.tibco.com/support/advisories/2017/06/tibco-security-advisory-june-28-2017-tibco-jasperreports-server-2017-0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.2");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "6.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
