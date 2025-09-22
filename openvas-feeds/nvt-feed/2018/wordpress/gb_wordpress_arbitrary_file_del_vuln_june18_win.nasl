# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813454");
  script_version("2023-03-01T10:20:05+0000");
  script_cve_id("CVE-2018-12895");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-05 18:42:00 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"creation_date", value:"2018-06-27 12:51:49 +0530 (Wed, 27 Jun 2018)");
  script_name("WordPress Arbitrary File Deletion Vulnerability (Jun 2018) - Windows");

  script_tag(name:"summary", value:"WordPress is prone to an arbitrary file deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of user input data in the 'wp-includes/post.php' script before
  passing on to a file deletion function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to delete any file of the wordPress installation and any other file
  on the server on which the PHP process user has the proper permissions to delete.
  Also capability of arbitrary file deletion can be used to circumvent some
  security measures and execute arbitrary code on the webserver.");

  script_tag(name:"affected", value:"All wordPress versions through version 4.9.6.");

  script_tag(name:"solution", value:"Update to version 4.9.7.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution");
  script_xref(name:"URL", value:"https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"4.9.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.9.7", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);