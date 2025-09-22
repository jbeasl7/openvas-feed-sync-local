# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140058");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-11-14 17:35:01 +0100 (Mon, 14 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Brocade NetIron OS Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Brocade NetIron OS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc) exit(0);

# Brocade NetIron MLX (System Mode: MLX), IronWare Version V5.6.0hT163 Compiled on Apr 27 2016 at 07:33:38 labeled as V5.6.00h
# Brocade NetIron CES, IronWare Version V5.6.0fT183 Compiled on Mar 27 2015 at 02:13:25 labeled as V5.6.00fb
# Brocade NetIron XMR (System Mode: XMR), IronWare Version V5.5.0dT163 Compiled on Oct  3 2013 at 13:31:00 labeled as V5.5.00d
# Brocade NetIron CER, Extended route scalability, IronWare Version V5.6.0bT183 Compiled on Jan 19 2014 at 11:42:28 labeled as V5.6.00b
if( "Brocade NetIron" >!< sysdesc || "IronWare" >!< sysdesc ) exit( 0 );

set_kb_item( name:'brocade_netiron/installed', value:TRUE );

cpe = 'cpe:/o:brocade:netiron_os';
vers = 'unknown';

version = eregmatch( pattern:'IronWare Version V([0-9.]+[^T]+)T([0-9]+)', string:sysdesc );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:'brocade_netiron/os/version', value:vers );
}

if( ! isnull( version[2] ) )
  set_kb_item( name:'brocade_netiron/os/build', value:version[2] ); # build?

register_product( cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp" );

os_register_and_report( os:"Brocade NetIron OS " + vers, cpe:cpe, banner_type:"SNMP sysdesc", banner:sysdesc, port:port, proto:"udp", desc:"Brocade NetIron OS Detection (SNMP)", runs_key:"unixoide" );

m = eregmatch( pattern:'^Brocade NetIron ([^ ,]+)', string:sysdesc );
if( ! isnull( m[1] ) )
  set_kb_item( name:"brocade_netiron/typ", value:m[1] );

report = build_detection_report( app:"Brocade NetIron OS", version:vers, install:port + "/udp", cpe:cpe, concluded:sysdesc );
log_message( port:port, data:report, proto:'udp');

exit( 0 );

