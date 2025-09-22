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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803845");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2011-3389", "CVE-2012-0883", "CVE-2012-2110", "CVE-2012-2311", "CVE-2012-2329",
                "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-5217", "CVE-2013-2355", "CVE-2013-2356",
                "CVE-2013-2357", "CVE-2013-2358", "CVE-2013-2359", "CVE-2013-2360", "CVE-2013-2361",
                "CVE-2013-2362", "CVE-2013-2363", "CVE-2013-2364", "CVE-2013-4821");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-07-30 11:22:25 +0530 (Tue, 30 Jul 2013)");
  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU02900)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 7.2.1 or later.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.2.1.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain elevated
  privileges, disclose sensitive information, perform unauthorized actions, or cause denial of
  service conditions.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61333");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61336");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61339");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61341");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61342");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61343");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/128");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/135");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c03839862");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"7.2.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"7.2.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);