# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/o:quest:kace_systems_management_appliance_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803735");
  script_version("2022-05-17T11:29:24+0000");
  script_tag(name:"last_modification", value:"2022-05-17 11:29:24 +0000 (Tue, 17 May 2022)");
  script_tag(name:"creation_date", value:"2013-08-12 20:18:38 +0530 (Mon, 12 Aug 2013)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1671");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Quest / Dell KACE K1000 Systems Management Appliance (SMA) <= 5.4.70402 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_quest_kace_sma_http_detect.nasl");
  script_mandatory_keys("quest/kace/sma/detected");

  script_tag(name:"summary", value:"Quest / Dell KACE K1000 Systems Management Appliance (SMA) is
  prone to multiple SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to asset.php, asset_type.php,
  metering.php, mi.php, replshare.php, kbot.php, history_log.php and service.php scripts are not
  properly sanitizing user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data.");

  script_tag(name:"affected", value:"Quest / Dell KACE K1000 SMA version 5.4.70402 and prior.");

  script_tag(name:"solution", value:"Update to version 5.5 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27039");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jul/194");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "5.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "5.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
