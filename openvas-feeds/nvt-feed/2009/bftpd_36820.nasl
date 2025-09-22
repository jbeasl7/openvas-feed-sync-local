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

CPE = "cpe:/a:bftpd:bftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100320");
  script_version("2021-08-31T13:35:08+0000");
  script_tag(name:"last_modification", value:"2021-08-31 13:35:08 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2009-10-28 11:13:14 +0100 (Wed, 28 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-4593");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Bftpd < 2.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_bftpd_detect.nasl");
  script_mandatory_keys("bftpd/detected");

  script_tag(name:"summary", value:"Bftpd is prone to an unspecified remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploits will cause the affected application to
  crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Bftpd 2.4 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 2.4 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36820");
  script_xref(name:"URL", value:"http://bftpd.sourceforge.net/news.html#032130");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);