# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103220");
  script_version("2022-08-11T10:10:35+0000");
  script_tag(name:"last_modification", value:"2022-08-11 10:10:35 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"creation_date", value:"2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_greenbone_os_http_detect.nasl", "gb_greenbone_os_snmp_detect.nasl", "gb_greenbone_os_ssh_detect.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"Consolidation of Greenbone Security Manager (GSM) / Greenbone OS
  (GOS) detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

SCRIPT_DESC = "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection Consolidation";

if( ! get_kb_item( "greenbone/gos/detected" ) )
  exit( 0 );

detected_version = "unknown";
detected_type    = "unknown";

foreach source( make_list( "http", "snmp", "ssh" ) ) {

  version_list = get_kb_list( "greenbone/gos/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"greenbone/gos/version", value:version );
      break;
    }
  }

  type_list = get_kb_list( "greenbone/gsm/" + source + "/*/type" );
  foreach type( type_list ) {
    if( type != "unknown" && detected_type == "unknown" ) {
      detected_type = type;
      set_kb_item( name:"greenbone/gsm/type", value:type );
      break;
    }
  }
}

if( detected_type != "unknown" ) {
  # nb: Those are "virtual" appliances so don't register a hardware CPE for these.
  # nb: Keep in sync with the pattern in gb_greenbone_os_snmp_detect.nasl
  if( egrep( string:detected_type, pattern:"(TRIAL|DEMO|ONE|MAVEN|150V|EXPO|25V|CE|CENO|DECA|TERA|PETA|EXA)", icase:TRUE ) )
    hw_app_cpe = "cpe:/a:greenbone:gsm_" + tolower( detected_type );
  else
    hw_app_cpe = "cpe:/h:greenbone:gsm_" + tolower( detected_type );
  app_type = detected_type;
} else {
  hw_app_cpe = "cpe:/h:greenbone:gsm_unknown_type";
  app_type = "Unknown Type";
}

os_cpe = "cpe:/o:greenbone:greenbone_os";

if( detected_version != "unknown" ) {
  os_register_and_report( os:"Greenbone OS (GOS)", version:detected_version, cpe:os_cpe, desc:SCRIPT_DESC, runs_key:"unixoide" );
  os_cpe += ":" + detected_version;
} else {
  os_register_and_report( os:"Greenbone OS (GOS)", cpe:os_cpe, desc:SCRIPT_DESC, runs_key:"unixoide" );
}

location = "/";

if( http_port = get_kb_list( "greenbone/gos/http/port" ) ) {
  foreach port( http_port ) {
    concluded = get_kb_item( "greenbone/gos/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "greenbone/gos/http/" + port + "/concludedUrl" );
    extra += '\n- HTTP(s) on port ' + port + '/tcp';
    if( concluded ) {
      concluded = str_replace( string:concluded, find:'\n', replace:'<newline>' );
      extra += '\n  Concluded from version/product identification result: ' + concluded;
    }

    if( concludedUrl )
      extra += '\n  Concluded from version/product identification location: ' + concludedUrl;

    register_product( cpe:hw_app_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

if( ssh_port = get_kb_list( "greenbone/gos/ssh/port" ) ) {
  foreach port( ssh_port ) {
    concluded = get_kb_item( "greenbone/gos/ssh/" + port + "/concluded" );
    extra += '\n- SSH on port ' + port + '/tcp';
    if( concluded )
      extra += '\n  Concluded from SSH banner / login: ' + concluded;

    register_product( cpe:hw_app_cpe, location:location, port:port, service:"ssh" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ssh" );
  }
}

if( snmp_port = get_kb_list( "greenbone/gos/snmp/port" ) ) {
  foreach port( snmp_port ) {
    concluded    = get_kb_item( "greenbone/gos/snmp/" + port + "/concluded" );
    concludedOID = get_kb_item( "greenbone/gos/snmp/" + port + "/concludedOID" );
    extra += '\n- SNMP on port ' + port + '/udp';
    if( concludedOID )
      extra += '\n  Concluded from SNMP OID(s):\n' + concludedOID;
    if( concluded )
      extra += '\n  Concluded from:\n' + concluded;

    register_product( cpe:hw_app_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

report = build_detection_report( app:"Greenbone OS (GOS)",
                                 version:detected_version,
                                 install:location,
                                 cpe:os_cpe );
report += '\n\n' + build_detection_report( app:"Greenbone Security Manager (GSM) " + app_type,
                                           install:location,
                                           cpe:hw_app_cpe,
                                           skip_version:TRUE );
if( extra ) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message( port:0, data:report );
exit( 0 );
