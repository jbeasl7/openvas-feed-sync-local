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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805692");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231", "CVE-2014-3523", "CVE-2014-3569",
                "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8142", "CVE-2014-8275",
                "CVE-2014-9427", "CVE-2014-9652", "CVE-2014-9653", "CVE-2014-9705", "CVE-2015-0204",
                "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0207", "CVE-2015-0208", "CVE-2015-0209",
                "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-0285", "CVE-2015-0286",
                "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0290", "CVE-2015-0291",
                "CVE-2015-0292", "CVE-2015-0293", "CVE-2015-1787", "CVE-2015-2301", "CVE-2015-2331",
                "CVE-2015-2348", "CVE-2015-2787", "CVE-2015-2134");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-07-27 14:14:07 +0530 (Mon, 27 Jul 2015)");

  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU03380)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.5.0.");

  script_tag(name:"solution", value:"Update to version 7.5.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c04746490");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75961");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"7.5.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.5.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);