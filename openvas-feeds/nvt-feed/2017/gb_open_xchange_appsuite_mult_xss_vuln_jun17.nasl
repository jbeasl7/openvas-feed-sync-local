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
  script_oid("1.3.6.1.4.1.25623.1.0.811134");
  script_version("2022-12-12T10:22:32+0000");
  script_cve_id("CVE-2015-1588");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-12 10:22:32 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:55:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-06-21 16:24:33 +0530 (Wed, 21 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Multiple Cross Site Scripting Vulnerabilities (Jun 2017)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the sanitation and cleaner engine does not
  properly filter HTML code from user-supplied input before displaying the input. A remote user can
  cause arbitrary scripting code to be executed by the target user's browser.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML in the browser of an unsuspecting user. This can lead to session
  hijacking or triggering unwanted actions via the web interface (sending mail, deleting data etc.).
  Potential attack vectors are E-Mail (via attachments) or Drive.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions 7.6.1-rev0 through
  7.6.1-rev20, 7.6.0-rev0 through 7.6.0-rev37 and 7.4.2-rev42 and prior.");

  script_tag(name:"solution", value:"Update to version 7.4.2-rev43, 7.6.0-rev38, 7.6.1-rev21 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535388/100/1100/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74350");
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

if(version_is_less(version: version, test_version: "7.4.2.43"))
  fix = "7.4.2-rev43";

else if(version =~ "^7\.6\.0" && version_is_less(version: version, test_version: "7.6.0.38"))
  fix = "7.6.0-rev38";

else if(version =~ "^7\.6\.1" && version_is_less(version: version, test_version: "7.6.1.21"))
  fix = "7.6.1-rev21";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
