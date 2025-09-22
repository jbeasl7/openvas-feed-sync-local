# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14262");
  script_version("2021-06-01T06:37:42+0000");
  script_tag(name:"last_modification", value:"2021-06-01 06:37:42 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2003-0069");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PuTTY window title escape character arbitrary command execution");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_putty_portable_detect.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("putty/detected");

  script_tag(name:"summary", value:"PuTTY is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"insight", value:"This version contains a flaw that may allow a malicious user
  to insert arbitrary commands and execute them. The issue is triggered when an attacker sends
  commands, preceded by terminal emulator escape sequences.");

  script_tag(name:"impact", value:"It is possible that the flaw may allow arbitrary code execution
  resulting in a loss of integrity.");

  script_tag(name:"affected", value:"PuTTY prior to version 0.54.");

  script_tag(name:"solution", value:"Update to version 0.54 or later.");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"0.54" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"0.54", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
