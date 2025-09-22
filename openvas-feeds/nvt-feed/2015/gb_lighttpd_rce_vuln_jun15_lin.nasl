# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805593");
  script_version("2023-02-01T10:08:40+0000");
  script_cve_id("CVE-2015-3200");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-02-01 10:08:40 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-24 02:59:00 +0000 (Sat, 24 Dec 2016)");
  script_tag(name:"creation_date", value:"2015-06-19 09:50:40 +0530 (Fri, 19 Jun 2015)");
  script_name("Lighttpd < 1.4.36 'http_auth.c' RCE Vulnerability - Linux");

  script_tag(name:"summary", value:"Lighttpd is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'http_auth.c' which does not
  properly validate user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to execute
  arbitrary code on affected system.");

  script_tag(name:"affected", value:"Lighttpd prior to version 1.4.36.");

  script_tag(name:"solution", value:"Update to version 1.4.36 or later.");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032405");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74813");
  script_xref(name:"URL", value:"http://jaanuskp.blogspot.in/2015/05/cve-2015-3200.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("sw_lighttpd_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("lighttpd/detected", "Host/runs_unixoide");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version: vers, test_version: "1.4.36" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.36" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
