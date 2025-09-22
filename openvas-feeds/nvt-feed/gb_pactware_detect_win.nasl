# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107603");
  script_version("2023-02-22T10:19:34+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:19:34 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-02-18 16:18:35 +0100 (Mon, 18 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PACTware Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of PACTware.");

  script_xref(name:"URL", value:"http://www.pactware.com");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull ( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );

    if( ! app_name || app_name !~ "PACTware [0-9.]+" )
      continue;

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc )
      location = loc;

    # Note: 'DisplayVersion' might contain a value that differs from the version used in advisories,
    #       so the contents of 'DisplayName' are used instead if a Servicepack is mentioned.
    #       If no Servicepack is mentioned, the data of 'DisplayVersion' might contain a value,
    #       that does not match exactly. In this case it has to be modified.

    if( dispvers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      if( app_name =~ "SP" ) {
        strip_vers = eregmatch( pattern:"(([0-9.]+) (SP[0-9])?)", string:app_name );
        version = strip_vers[2] + tolower( strip_vers[3] );
      }
      else {
        mod_vers = split( dispvers, sep:".", keep:FALSE );
        vers_part = str_replace(find:"0", string: mod_vers[2], replace:".", count:1);
        version = mod_vers[0] + "." + mod_vers[1] + "." + vers_part;
      }
      concluded += '\nDisplayVersion: ' + dispvers;

    }

    set_kb_item( name:"pactware/pactware/detected", value:TRUE );

    register_and_report_cpe( app:app_name, ver:version, concluded:concluded,
                             base:"cpe:/a:pactware:pactware:", expr:"^([0-9.a-z]+)",
                             insloc:location, regService:"smb-login", regPort:0 );
  # Note: App can be installed in different versions on the same machine, so no exit after first match.
  }
}

exit( 0 );
