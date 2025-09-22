# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112116");
  script_version("2022-11-10T10:12:04+0000");
  script_tag(name:"last_modification", value:"2022-11-10 10:12:04 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2019-06-17 12:57:00 +0200 (Mon, 17 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-17 15:43:00 +0000 (Mon, 17 Jun 2019)");

  script_cve_id("CVE-2013-7472");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Count per Day Plugin < 3.2.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/count-per-day/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Count per Day' is prone to an XSS vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject malicious content into an affected site.");
  script_tag(name:"affected", value:"WordPress Count per Day plugin before version 3.2.6.");
  script_tag(name:"solution", value:"Update to version 3.2.6 or later.");

  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2013/03/05/2");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/count-per-day/#developers");

  exit(0);
}

CPE = "cpe:/a:count_per_day_project:count_per_day";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
