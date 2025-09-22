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
  script_oid("1.3.6.1.4.1.25623.1.0.112046");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-09-13 07:56:31 +0200 (Wed, 13 Sep 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 22:15:00 +0000 (Thu, 29 Oct 2020)");

  script_cve_id("CVE-2015-9228");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress NextGEN Gallery Plugin < 2.1.15 Malicious File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/nextgen-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'NextGEN Gallery' is prone to a malicious
  file upload vulnerability.");

  script_tag(name:"insight", value:"In post-new.php unrestricted file upload is available via the name
  parameter, if a file extension is changed from .jpg to .php.

  Even though credentials are required to upload file into the server, any new combined vulnerability
  can allow an attacker to upload shell into the server which gives entire root access of the
  server.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will give the
  attacker root access to the server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress NextGEN Gallery plugin before 2.1.15.");

  script_tag(name:"solution", value:"Update to version 2.1.15 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/nextgen-gallery/#developers");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135061/WordPress-NextGEN-Gallery-2.1.10-Shell-Upload.html");

  exit(0);
}

CPE = "cpe:/a:imagely:nextgen_gallery";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.1.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
