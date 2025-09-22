# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:teamspeak:teamspeak3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100682");
  script_version("2023-01-11T10:12:37+0000");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"creation_date", value:"2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TeamSpeak 3 Server < 3.0.0-beta25 Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_teamspeak_server_tcp_detect.nasl");
  script_mandatory_keys("teamspeak3_server/tcp/detected"); # nb: Only the TCP detection is currently grabbing the version

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40918");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/teamspeakrack-adv.txt");
  script_xref(name:"URL", value:"http://forum.teamspeak.com/showthread.php?t=55646");
  script_xref(name:"URL", value:"http://forum.teamspeak.com/showthread.php?t=55643");

  script_tag(name:"summary", value:"TeamSpeak 3 server is prone to multiple remote vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A security-pass vulnerability

  - A denial-of-service vulnerability

  - Multiple denial-of-service vulnerabilities due to a NULL-pointer dereference condition");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary
  commands within the context of the affected application, bypass certain security restrictions and
  crash the affected application. Other attacks are also possible.");

  script_tag(name:"affected", value:"TeamSpeak 3 server versions prior to 3.0.0-beta25.");

  script_tag(name:"solution", value:"Update to version 3.0.0-beta25 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! ver = get_kb_item( "teamspeak3_server/" + port ) )
  exit( 0 );

if( "build" >< ver ) {
  vers = eregmatch( pattern:"([^ ]+)", string:ver );
  vers = vers[1];
} else {
  vers = ver;
}

if( isnull( vers ) )
  exit( 0 );

if( "-beta" >< vers )
  vers = str_replace( string:vers, find:"-beta", replace:"." );

if( version_is_less( version:vers, test_version:"3.0.0.25" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.0.0-beta25" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
