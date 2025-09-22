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
  script_oid("1.3.6.1.4.1.25623.1.0.112577");
  script_version("2022-11-09T10:31:49+0000");
  script_tag(name:"last_modification", value:"2022-11-09 10:31:49 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2019-05-13 13:35:00 +0200 (Mon, 13 May 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 16:13:00 +0000 (Wed, 24 Feb 2021)");

  script_cve_id("CVE-2019-9576");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Blog2Social Plugin < 5.0.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/blog2social/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Blog2Social' is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject malicious content into an affected site.");
  script_tag(name:"affected", value:"WordPress Blog2Social plugin before version 5.0.3.");
  script_tag(name:"solution", value:"Update to version 5.0.3 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/blog2social/#developers");
  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/02/05/6");
  script_xref(name:"URL", value:"https://security-consulting.icu/blog/2019/02/wordpress-blog2social-xss/");

  exit(0);
}

CPE = "cpe:/a:adenion:blog2social";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less(version: version, test_version: "5.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
