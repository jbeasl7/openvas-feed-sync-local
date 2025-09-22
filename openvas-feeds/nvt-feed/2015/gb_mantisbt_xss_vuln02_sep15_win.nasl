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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805975");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-9272");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-09-08 18:15:16 +0530 (Tue, 08 Sep 2015)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MantisBT 1.1.2 - 1.2.17 XSS Vulnerability - Windows");

  script_tag(name:"summary", value:"MantisBT is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the function
  'string_insert_hrefs' doesn't validate the protocol in core/string_api.php
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via the
  'config_option' parameter.");

  script_tag(name:"affected", value:"MantisBT versions 1.1.2 through 1.2.17.");

  script_tag(name:"solution", value:"Update to version 1.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71375");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q4/867");
  script_xref(name:"URL", value:"https://www.mantisbt.org/bugs/view.php?id=17297");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");

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

##1.2.0a1 through 1.2.17== https://www.mantisbt.org/blog/?tag=release&paged=4
##Certain 1.1.x branch versions released after 1.2.0a1 are also vulnerable
if (version_in_range(version: version, test_version: "1.1.2", test_version2: "1.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
