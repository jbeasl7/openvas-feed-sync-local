# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900983");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Axon Virtual PBX Version Detection (SIP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl", "gb_axon_virtual_pbx_web_detect.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"This script performs SIP based detection of Axon Virtual PBX.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("sip.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner( port:port, proto:proto );

if( banner && "Axon Virtual PBX" >< banner ) {

  version = "unknown";

  ver = eregmatch( pattern:"Axon Virtual PBX ([0-9.]+)", string:banner );

  if( ! isnull( ver[1] ) )
    version = ver[1];

  set_kb_item( name:"Axon-Virtual-PBX/installed", value:TRUE );
  set_kb_item( name:"Axon-Virtual-PBX/sip/" + port + "/ver", value:version );
  set_kb_item( name:"Axon-Virtual-PBX/sip/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nch:axon_virtual_pbx:" );
  if( ! cpe )
    cpe = "cpe:/a:nch:axon_virtual_pbx";

  location = port + "/" + proto;

  register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );
  log_message( data:build_detection_report( app:"Axon Virtual PBX",
                                            version:version,
                                            install:location,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port,
                                            proto:proto );
}

exit( 0 );
