# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:apache:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14800");
  script_version("2022-06-03T09:40:54+0000");
  script_tag(name:"last_modification", value:"2022-06-03 09:40:54 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2004-0749");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Subversion Information Disclosure Vulnerability (Nov 2005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("gb_apache_subversion_detect.nasl");
  script_mandatory_keys("apache/subversion/detected");

  script_tag(name:"summary", value:"A flaw exists in the Apache module mod_authz_svn, which fails
  to properly restrict access to metadata within unreadable paths.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can read metadata in unreadable paths, which can
  contain sensitive information such as logs and paths.");

  script_tag(name:"affected", value:"Apache Subversion prior to version 1.0.8 and version 1.1.x
  prior to version 1.1.0-rc4.");

  script_tag(name:"solution", value:"Update to version 1.0.8, 1.1.0-rc4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11243");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
