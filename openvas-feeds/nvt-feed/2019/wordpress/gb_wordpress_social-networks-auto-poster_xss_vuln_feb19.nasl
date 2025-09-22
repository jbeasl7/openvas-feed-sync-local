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
  script_oid("1.3.6.1.4.1.25623.1.0.112559");
  script_version("2023-05-30T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-30 09:08:51 +0000 (Tue, 30 May 2023)");
  script_tag(name:"creation_date", value:"2019-04-01 12:45:00 +0100 (Mon, 01 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 18:17:00 +0000 (Fri, 26 May 2023)");

  script_cve_id("CVE-2019-9911");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Social Networks Auto-Poster Plugin < 4.2.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/social-networks-auto-poster-facebook-twitter-g/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Social Networks Auto-Poster' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject malicious
  content into an affected site.");

  script_tag(name:"affected", value:"WordPress Social Networks Auto-Poster plugin prior to
  version 4.2.8.");

  script_tag(name:"solution", value:"Update to version 4.2.8 or later.");

  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/02/05/12");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/social-networks-auto-poster-facebook-twitter-g/#developers");

  exit(0);
}

CPE = "cpe:/a:nextscripts:social_networks_auto_poster";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.2.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
