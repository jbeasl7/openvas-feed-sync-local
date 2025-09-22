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
  script_oid("1.3.6.1.4.1.25623.1.0.800097");
  script_version("2022-09-01T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-09-01 10:11:07 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5734");
  script_name("Merak Mail Server Web Mail < 9.4.0 IMG HTML Tag Script Insertion Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_consolidation.nasl");
  script_mandatory_keys("icewarp/mailserver/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32770");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47533");
  script_xref(name:"URL", value:"http://blog.vijatov.com/index.php?itemid=11");

  script_tag(name:"summary", value:"Merak Mail Server is prone to a script injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Input passed via <IMG> HTML tags in emails are not properly
  sanitised before being displayed in the users system.");

  script_tag(name:"impact", value:"Successful exploitation could result in insertion of arbitrary
  HTML and script code via a specially crafted email in a user's browser session in the context of
  an affected site.");

  script_tag(name:"affected", value:"Merak Mail Server 9.3.2 and prior.");

  script_tag(name:"solution", value:"Update to version 9.4.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "9.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
