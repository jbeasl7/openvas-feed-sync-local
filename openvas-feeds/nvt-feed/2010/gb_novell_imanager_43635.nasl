# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:netiq:imanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100835");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Novell iManager <= 2.7.3.2 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_netiq_imanager_http_detect.nasl");
  script_mandatory_keys("netiq/imanager/detected");

  script_tag(name:"summary", value:"Novell iManager is prone to an arbitrary file upload
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to upload arbitrary files to
  the affected computer. This can result in arbitrary code execution within the context of the
  vulnerable application.");

  script_tag(name:"affected", value:"Novell iManager version 2.7.3.2 and prior.");

  script_tag(name:"solution", value:"See the referenced advisories for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43635");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7006515");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-190/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.7.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
