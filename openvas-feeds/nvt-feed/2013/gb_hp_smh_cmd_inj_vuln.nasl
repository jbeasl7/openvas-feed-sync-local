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
  script_oid("1.3.6.1.4.1.25623.1.0.803846");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3576");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-07-30 13:30:42 +0530 (Tue, 30 Jul 2013)");
  script_name("HP/HPE System Management Homepage (SMH) Command Injection Vulnerability (HPSBMU02917)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to a command
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 7.2.2 or later.");

  script_tag(name:"insight", value:"The flaw is triggered when the ginkgosnmp.inc script uses the
  last path segment of the current requested URL path in an exec call without properly sanitizing
  the content.");

  script_tag(name:"affected", value:"HP/HPE SMH version 7.2.1.3 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote
  attacker to execute arbitrary commands.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60471");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/735364");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c03895050");
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

if(version_is_less_equal(version:version, test_version:"7.2.1.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"7.2.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);