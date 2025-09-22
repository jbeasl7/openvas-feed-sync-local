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
  script_oid("1.3.6.1.4.1.25623.1.0.113337");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-02-15 10:07:44 +0100 (Fri, 15 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine OpManager Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_manage_engine_opmanager_http_detect.nasl", "gb_manage_engine_opmanager_smb_detect.nasl");
  script_mandatory_keys("manageengine/opmanager/detected");

  script_tag(name:"summary", value:"Consolidation of ManageEngine OpManager detections.");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-monitoring/");

  exit(0);
}

if( ! get_kb_item( "manageengine/opmanager/detected" ) )
  exit( 0 );

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source( make_list( "smb", "http" ) ) {
  version_list = get_kb_list( "manageengine/opmanager/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      #detected_version = version;
      detected_build = version;
      if (strlen(version) == 6)
        detected_version = substr(version, 0, 1) + "." + version[2];
      else
        detected_version = version[0] + "." + version[1];
      break;
    }
  }
}

cpe = build_cpe( value:detected_version + "build" + detected_build, exp:"^([0-9.]+)(build[0-9]+)",
                 base:"cpe:/a:zohocorp:manageengine_opmanager:" );
if( ! cpe )
  cpe = "cpe:/a:zohocorp:manageengine_opmanager";

if( ! isnull( concluded = get_kb_item( "manageengine/opmanager/smb/0/concluded" ) ) ) {
  loc = get_kb_item( "manageengine/opmanager/smb/0/location" );
  extra += 'Local Detection over SMB:\n';
  extra += '\n  Location:      ' + loc;
  extra += '\n  Concluded from:\n' + concluded;

  register_product( cpe:cpe, location:loc, port:0, service:"smb-login" );
}

if( http_ports = get_kb_list( "manageengine/opmanager/http/port" ) ) {
  if( extra )
    extra += '\n\n';

  extra += 'Remote Detection over HTTP(s):\n';

  foreach port( http_ports ) {
    concluded = get_kb_item( "manageengine/opmanager/http/" + port + "/concluded" );
    loc = get_kb_item( "manageengine/opmanager/http/" + port + "/location" );
    extra += '  Port:           ' + port + '/tcp\n';
    extra += '  Location:       ' + loc;

    if( concluded )
      extra += '\n  Concluded from: ' + concluded;

    register_product( cpe:cpe, location:loc, port:port, service:"www" );
  }
}

set_kb_item( name: "manageengine/products/detected", value: TRUE );

report = build_detection_report( app: "ManageEngine OpManager", version: detected_version, build: detected_build,
                                 cpe: cpe, install: location);

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:report );

exit( 0 );
