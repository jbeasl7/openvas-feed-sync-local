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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107129");
  script_version("2021-09-28T14:43:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-28 14:43:50 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-01-18 16:11:25 +0700 (Wed, 18 Jan 2017)");

  script_tag(name:"qod_type", value:"registry");

  script_name("ManageEngine ADManager Plus Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of ManageEngine ADManager Plus.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

arch = get_kb_item( "SMB/Windows/Arch" );
if( ! arch )
  exit( 0 );

if( "x86" >< arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key: key ) ) {
    app_name = registry_get_sz( key: key + item, item: "DisplayName" );

    if( ! app_name || "ADManager Plus" >!< app_name )
      continue;

    concluded  = "  Registry Key:   " + key + item + '\n';
    concluded += "  DisplayName:    " + app_name;
    location = "unknown";
    version = "unknown";
    build = "unknown";

    if( loc = registry_get_sz( key: key + item, item: "InstallLocation" ) ) {
      location = loc;

      # Registry key "DisplayVersion" does not contain the correct version / build information.
      # Due to that, we need to fetch the values from the file "product.conf" in subfolder conf
      # if the product location has been detected.
      # Content of /conf/product.conf:
      #
      # product.name=ManageEngine ADManager Plus
      # product.version=7.1.0
      # product.build_number=7113
      # product.processor_architecture=64
      # product.auth.domain.name=ADManager Plus Authentication
      # product.ha_support=true

      path = location + '\\conf\\product.conf';
      version_info = smb_read_file( fullpath: path, offset: 0, count: 300 );
      versq = eregmatch( pattern: "product\.version=([0-9.]+)", string: version_info );
      buildq = eregmatch( pattern: "product\.build_number=([0-9.]+)", string: version_info );

      if( versq[1] ) {
        # Make versionstring NVD conform
        vers = eregmatch( string: versq[1], pattern: "^([0-9]+\.[0-9]+)" );
        if( vers[1] ) {
          version = vers[1];
          concluded += '\n  Version:        ' + version + ' (extracted from ' + path + ')';
        }
      }

      if( buildq[1] ) {
        build = buildq[1];
        concluded += '\n  Build:          ' + build + ' (extracted from ' + path + ')';
      }
    }

    if( regvers = registry_get_sz( key: key + item, item: "DisplayVersion" ) )
      concluded += '\n  DisplayVersion: ' + regvers;

    set_kb_item( name: "manageengine/admanager_plus/detected", value: TRUE );
    set_kb_item( name: "manageengine/admanager_plus/smb-login/0/detected", value: TRUE );
    set_kb_item( name: "manageengine/admanager_plus/smb-login/0/location", value: location );
    set_kb_item( name: "manageengine/admanager_plus/smb-login/0/version", value: version );
    set_kb_item( name: "manageengine/admanager_plus/smb-login/0/build", value: build );
    set_kb_item( name: "manageengine/admanager_plus/smb-login/0/concluded", value: concluded );
  }
}

exit( 0 );
