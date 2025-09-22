# Copyright (C) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112236");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-02-20 11:30:00 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-08 16:23:00 +0000 (Mon, 08 Jul 2019)");

  script_cve_id("CVE-2015-2324");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Photo Gallery Plugin < 1.2.13 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/photo-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Photo Gallery' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The XSS vulnerability in the filemanager allows remote
  authenticated users with edit permission to inject arbitrary web script or HTML via unspecified
  vectors.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Web-Dorado 'Photo Gallery by WD - Responsive Photo
  Gallery' plugin before 1.2.13.");

  script_tag(name:"solution", value:"Update to version 1.2.13 or later.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-15-009");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/photo-gallery/#developers");

  exit(0);
}

CPE = "cpe:/a:10web:photo_gallery";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.2.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
