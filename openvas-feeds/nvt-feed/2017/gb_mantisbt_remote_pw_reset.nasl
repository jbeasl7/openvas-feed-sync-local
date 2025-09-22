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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108140");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-04-18 08:00:00 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-20 14:57:00 +0000 (Fri, 20 Jan 2023)");
  script_cve_id("CVE-2017-7615");

  script_name("MantisBT 1.3.x < 1.3.10, 2.x < 2.3.0 Pre-Auth Remote Password Reset Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/http/detected");

  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/MANTIS-BUG-TRACKER-PRE-AUTH-REMOTE-PASSWORD-RESET.txt");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=22690");

  script_tag(name:"summary", value:"MantisBT is prone to a remote password reset vulnerability.");

  script_tag(name:"insight", value:"The flaw exists because MantisBT allows arbitrary password reset and unauthenticated admin access
  via an empty confirm_hash value to verify.php.");

  script_tag(name:"vuldetect", value:"Check if it is possible to reset an admin/user password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote unauthenticated attacker to reset an admin/user password.");

  script_tag(name:"affected", value:"MantisBT versions 1.3.x before 1.3.10 and 2.3.0.");

  script_tag(name:"solution", value:"Update to version 1.3.10, 2.3.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/verify.php?id=1&confirm_hash=";

# Used the form here as the message of the confirmation might be translated
if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'<form id="account-update-form" method="post" action="account_update\\.php">' ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
