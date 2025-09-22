# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112053");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-09-25 09:35:51 +0200 (Mon, 25 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-01 06:15:00 +0000 (Sun, 01 Sep 2019)");

  script_cve_id("CVE-2015-4089");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Fastest Cache Plugin < 0.8.3.5 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-fastest-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Fastest Cache' is prone to multiple
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"insight", value:"The CSRF vulnerabilities in the optionsPageRequest function in
  admin.php allow remote attackers to hijack the authentication of unspecified victims for requests
  that call the (1) saveOption, (2) deleteCache, (3) deleteCssAndJsCache, or (4) addCacheTimeout
  method via the wpFastestCachePage parameter in the WpFastestCacheOptions/ page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Fastest Cache plugin version 0.8.3.4 and prior.");

  script_tag(name:"solution", value:"Update to version 0.8.3.5 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-fastest-cache/#developers");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/05/26/20");

  exit(0);
}

CPE = "cpe:/a:wpfastestcache:wp_fastest_cache";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.8.3.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.8.3.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
