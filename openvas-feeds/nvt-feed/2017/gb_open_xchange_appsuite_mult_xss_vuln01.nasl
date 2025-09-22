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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809850");
  script_version("2022-12-12T10:22:32+0000");
  script_cve_id("CVE-2016-5124");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-12 10:22:32 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-19 15:46:00 +0000 (Fri, 19 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-01-02 15:30:00 +0530 (Mon, 02 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Multiple XSS Vulnerabilities - 01");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper sanitization of
  user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected application.
  This may let the attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions 7.6.2-rev0 through
  7.6.2-rev54, 7.6.3-rev0 through 7.6.3-rev12, 7.8.0-rev0 through 7.8.0-rev31 and 7.8.1-rev0 through
  7.8.1-rev13.");

  script_tag(name:"solution", value:"Update to version 7.8.1-rev14, 7.6.2-rev55, 7.6.3-rev13,
  7.8.0-rev32 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91775");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/137894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/538892/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if(version =~ "^7\.8\.1" && version_is_less(version: version, test_version: "7.8.1.14"))
  fix = "7.8.1-rev14";

else if(version =~ "^7\.6\.2" && version_is_less(version: version, test_version: "7.6.2.55"))
  fix = "7.6.2-rev55";

else if(version =~ "^7\.6\.3" && version_is_less(version: version, test_version: "7.6.3.13"))
  fix = "7.6.3-rev13";

else if(version =~ "^7\.8\.0" && version_is_less(version: version, test_version: "7.8.0.32"))
  fix = "7.8.0-rev32";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
