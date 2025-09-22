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

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100295");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress 0.804 - 0.812.1 LFI Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to a local file include (LFI) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver
  process. This may allow the attacker to compromise the application and the underlying computer,
  other attacks are also possible.");

  script_tag(name:"affected", value:"FlatPress version 0.804 through 0.812.1.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36543");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53589");
  script_xref(name:"URL", value:"https://sourceforge.net/project/shownotes.php?group_id=157089&release_id=628765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/506816");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "0.804", test_version2: "0.812.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
