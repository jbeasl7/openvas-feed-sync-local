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
  script_oid("1.3.6.1.4.1.25623.1.0.807598");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2011-4969", "CVE-2015-3194", "CVE-2015-3195", "CVE-2016-0705", "CVE-2016-0799",
                "CVE-2016-2842", "CVE-2015-3237", "CVE-2015-7995", "CVE-2015-8035", "CVE-2007-6750",
                "CVE-2016-2015");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-20 16:59:00 +0000 (Wed, 20 Feb 2019)");
  script_tag(name:"creation_date", value:"2016-05-19 15:47:50 +0530 (Thu, 19 May 2016)");
  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU03593)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain and modify
  sensitive information and also remote attackers to execute arbitrary code and to obtain sensitive
  information.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.5.5.");

  script_tag(name:"solution", value:"Update to version 7.5.5 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c05111017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58458");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78623");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78626");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77325");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21865");

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

if(version_is_less(version:vers, test_version:"7.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.5.5");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);