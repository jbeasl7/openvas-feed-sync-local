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

CPE = "cpe:/a:zohocorp:manageengine_admanager_plus";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113106");
  script_version("2021-09-27T14:27:18+0000");
  script_tag(name:"last_modification", value:"2021-09-27 14:27:18 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"creation_date", value:"2018-02-08 11:30:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-13 16:38:00 +0000 (Tue, 13 Mar 2018)");

  script_cve_id("CVE-2017-17552");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine ADManager Plus < 6.6 build 6620 URL Redirection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_admanager_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/admanager_plus/detected");

  script_tag(name:"summary", value:"ManageEngine ADManager Plus is prone to an URL redirection attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can perform a URL redirection attack via a specially
  crafted URL, specifically via the src parameter.");

  script_tag(name:"impact", value:"Successful exploitation may result in a bypass of CSRF protection
  or potentially masquerading a malicious URL as trusted.");

  script_tag(name:"affected", value:"ManageEngine ADManager Plus through version 6.6 build 6613.");

  script_tag(name:"solution", value:"Update to version 6.6 build 6620 or later.");

  script_xref(name:"URL", value:"https://umbrielsecurity.wordpress.com/2018/01/31/dangerous-url-redirection-and-csrf-in-zoho-manageengine-ad-manager-plus-cve-2017-17552/");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/ad-manager/release-notes.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( !infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

vers = eregmatch(pattern: "([0-9]+\.[0-9])([0-9]+)", string: version);
if (!isnull(vers[1])) {
  rep_vers = vers[1];
  build = vers[2];
}

if( version_is_less_equal( version: version, test_version: "6.66613" ) ) {
  report = report_fixed_ver( installed_version: rep_vers, installed_build: build,
                             fixed_version: "6.6", fixed_build: "6620", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
