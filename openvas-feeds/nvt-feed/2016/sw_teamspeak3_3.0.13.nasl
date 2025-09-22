# Copyright (C) 2016 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111113");
  script_version("2023-01-11T10:12:37+0000");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-08-15 15:00:00 +0200 (Mon, 15 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("TeamSpeak 3 Server <= 3.0.13 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("General");
  script_dependencies("gb_teamspeak_server_tcp_detect.nasl");
  script_mandatory_keys("teamspeak3_server/tcp/detected"); # nb: Only the TCP detection is currently grabbing the version

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Aug/61");
  script_xref(name:"URL", value:"http://forum.teamspeak.com/threads/126318-TeamSpeak-3-Server-3-0-13-2-released?p=434139#post434139");

  script_tag(name:"summary", value:"TeamSpeak 3 server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Remote code execution

  - Information disclosure

  - Denial-of-Service");

  script_tag(name:"impact", value:"Exploiting this vulnerability may allow an attacker execute
  arbitrary code on the TeamSpeak 3 server or cause a Denial-of-Service of the affected service.");

  script_tag(name:"affected", value:"TeamSpeak 3 server versions up to 3.0.13.");

  script_tag(name:"solution", value:"Update to version 3.0.13.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:ver, test_version:"3.0", test_version2:"3.0.13" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.0.13.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
