# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804858");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2013-4545", "CVE-2013-6420", "CVE-2013-6422", "CVE-2013-6712", "CVE-2014-2640",
                "CVE-2014-2641", "CVE-2014-2642");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-10-14 11:52:11 +0530 (Tue, 14 Oct 2014)");

  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU03112)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists due to:

  - An error as HTTP requests to certain scripts do not require multiple steps,
    explicit confirmation, or a unique token when performing sensitive actions.

  - An error as application does not validate user-supplied input.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform
  clickjacking attacks, perform a Cross-Site Request Forgery attack or execute arbitrary script code
  in a user's browser session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.4.");

  script_tag(name:"solution", value:"Update to version 7.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c04463322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70208");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"7.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);