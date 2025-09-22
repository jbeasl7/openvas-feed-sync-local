# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813442");
  script_version("2022-12-12T10:22:32+0000");
  script_cve_id("CVE-2018-5754");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-12 10:22:32 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:42:00 +0000 (Thu, 02 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-06-19 11:36:20 +0530 (Tue, 19 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite XSS Vulnerability (Jun 2018)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the office-web component in
  Open-Xchange OX App Suite. Script code within Presentations is being executed when transferring it
  to the clipboard. This can be done by 'copying' or 'cutting' text using keyboard commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute malicious
  script code within a users context which can lead to session hijacking or triggering unwanted
  actions via the web interface like sending mail, deleting data etc.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite before 7.8.3-rev12 and 7.8.4 before
  7.8.4-rev9.");

  script_tag(name:"solution", value:"Update to version 7.8.3-rev12, 7.8.4-rev9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44881");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Jun/23");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/148118");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(version_is_less(version: version, test_version: "7.8.3.12"))
  fix = "7.8.3-rev12";

else if(version_in_range(version: version, test_version: "7.8.4", test_version2: "7.8.4.8"))
  fix = "7.8.4-rev9";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
