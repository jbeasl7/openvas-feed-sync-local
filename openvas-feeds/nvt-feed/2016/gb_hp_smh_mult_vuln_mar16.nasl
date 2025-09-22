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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807526");
  script_version("2021-10-14T13:27:28+0000");
  script_cve_id("CVE-2015-1793", "CVE-2015-4024", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1791",
                "CVE-2015-1790", "CVE-2015-1792", "CVE-2015-3143", "CVE-2015-3145", "CVE-2015-3148",
                "CVE-2015-4000", "CVE-2016-1993", "CVE-2016-1994", "CVE-2016-1995", "CVE-2016-1996");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-14 13:27:28 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:24:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-03-22 12:10:54 +0530 (Tue, 22 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU03546)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain and modify
  sensitive information and also remote attackers to execute arbitrary code and to obtain sensitive
  information.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.5.4.");

  script_tag(name:"solution", value:"Update to version 7.5.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c05045763");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"7.5.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.5.4");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);