# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:icewarp:mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100168");
  script_version("2022-09-01T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-09-01 10:11:07 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1516");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_name("IceWarp Merak Mail Server < 9.4.2 'Base64FileEncode()' Stack-Based Buffer Overflow Vulnerability");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_consolidation.nasl");
  script_mandatory_keys("icewarp/mailserver/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34739");

  script_tag(name:"summary", value:"IceWarp Merak Mail Server is prone to a stack-based buffer
  overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the application fails to bounds-check
  user-supplied data before copying it into an insufficiently sized buffer.");

  script_tag(name:"impact", value:"An attacker could exploit this issue to execute arbitrary code in
  the context of the affected application. Failed exploit attempts will likely result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"IceWarp Merak Mail Server 9.4.1 is vulnerable. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"Update to version 9.4.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "9.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"9.4.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
