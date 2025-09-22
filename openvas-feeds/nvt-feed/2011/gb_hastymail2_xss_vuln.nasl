# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:hastymail:hastymail2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801576");
  script_version("2022-04-06T08:30:48+0000");
  script_tag(name:"last_modification", value:"2022-04-06 08:30:48 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-4646");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hastymail2 < 1.01 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hastymail2_detect.nasl");
  script_mandatory_keys("hastymail2/detected");

  script_tag(name:"summary", value:"Hastymail2 is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of crafted background
  attribute within a cell in a TABLE element which allows remote attackers to inject arbitrary web
  script or HTML.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Hastymail2 prior to version 1.01.");

  script_tag(name:"solution", value:"Update to version 1.01 or later.");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/01/05/3");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/01/06/14");

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

if (version_is_less(version: version, test_version: "1.01")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.01", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
