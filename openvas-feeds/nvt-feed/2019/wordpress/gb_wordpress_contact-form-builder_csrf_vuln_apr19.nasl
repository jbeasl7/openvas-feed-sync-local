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
  script_oid("1.3.6.1.4.1.25623.1.0.112569");
  script_version("2023-03-02T10:19:53+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-04-29 10:53:00 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 14:38:00 +0000 (Mon, 27 Feb 2023)");

  script_cve_id("CVE-2019-11557");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Contact Form Builder Plugin < 1.0.69 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/contact-form-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Contact Form Builder' is prone to a CSRF vulnerability.");
  script_tag(name:"insight", value:"The plugin allows CSRF via the wp-admin/admin-ajax.php action parameter,
  resulting in a local file inclusion via directory traversal, because there can be a discrepancy between
  the $_POST['action'] value and the $_GET['action'] value, with the latter being unsanitized.");
  script_tag(name:"affected", value:"WordPress Contact Form Builder plugin before version 1.0.69.");
  script_tag(name:"solution", value:"Update to version 1.0.69 or later.");

  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/04/23/1");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/contact-form-builder/#developers");

  exit(0);
}

CPE = "cpe:/a:web-dorado:wp_form_builder";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.0.69" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.0.69", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
