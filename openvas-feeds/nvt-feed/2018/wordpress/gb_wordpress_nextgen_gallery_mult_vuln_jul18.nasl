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
  script_oid("1.3.6.1.4.1.25623.1.0.112326");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-07-16 11:20:14 +0200 (Mon, 16 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-16 19:08:00 +0000 (Fri, 16 Aug 2019)");

  script_cve_id("CVE-2016-6565", "CVE-2016-10889");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress NextGEN Gallery Plugin < 2.1.57 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/nextgen-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Imagely NextGen Gallery' is prone to
  multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-6565: The plugin does not properly validate user input in the cssfile parameter of a
  HTTP POST request, which may allow an authenticated user to read arbitrary files from the server, or
  execute arbitrary code on the server in some circumstances (dependent on server configuration).

  - CVE-2016-10889: The plugin has SQL injection via a gallery name.");

  script_tag(name:"impact", value:"An authenticated user may be able to read arbitrary files on the
  server, execute code on the server by including a malicious local file in a formatted server request
  or read or modify data in the database.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress NextGEN Gallery plugin before 2.1.57.");

  script_tag(name:"solution", value:"Update to version 2.1.57 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/nextgen-gallery/#developers");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94356");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/346175");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4b215a99-b1e7-4736-b859-92ceac3aad9c");

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

if( version_is_less( version: version, test_version: "2.1.57" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.57", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
