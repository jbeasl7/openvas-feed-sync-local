# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805319");
  script_version("2022-02-23T09:58:00+0000");
  script_tag(name:"last_modification", value:"2022-02-23 09:58:00 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-01-23 10:22:50 +0530 (Fri, 23 Jan 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9450");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zabbix Multiple SQLi Vulnerabilities (Jan 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zabbix_http_detect.nasl");
  script_mandatory_keys("zabbix/detected");

  script_tag(name:"summary", value:"Zabbix is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as input passed via the 'periods' and
  'itemid' GET parameter to chart_bar.php is not properly sanitised before being used in an SQL
  query.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Zabbix versions before 1.8.22, 2.0.x before 2.0.14, and 2.2.x
  before 2.2.8.");

  script_tag(name:"solution", value:"Update to version 1.8.22, 2.0.14, 2.2.8 or later.");

  script_xref(name:"URL", value:"http://www.zabbix.com/rn2.2.8.php");
  script_xref(name:"URL", value:"http://www.zabbix.com/rn1.8.22.php");
  script_xref(name:"URL", value:"http://www.zabbix.com/rn2.0.14.php");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-8582");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.8.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.2", test_version_up: "2.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
