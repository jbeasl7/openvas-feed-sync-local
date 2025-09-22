# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112117");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-11-10 13:04:05 +0100 (Fri, 10 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("pfSense Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of pfSense.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

if( ! sysdesc = snmp_get_sysdescr(port:port ) )
  exit( 0 );

# pfSense 2.4.4 without patch:
# pfSense  2.4.4-RELEASE pfSense FreeBSD 11.2-RELEASE-p3 amd64
# pfsense 2.4.4 with p3:
# pfSense  2.4.4-RELEASE pfSense FreeBSD 11.2-RELEASE-p10 amd64
if ( "pfSense" >< sysdesc ) {

  version = "unknown";

  set_kb_item( name:"pfsense/detected", value:TRUE );
  set_kb_item( name:"pfsense/snmp/detected", value:TRUE );
  set_kb_item( name:"pfsense/snmp/port", value:port );

  vers = eregmatch( pattern:"^pfSense .* ([0-9.]+)-RELEASE .* FreeBSD", string:sysdesc );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"pfsense/snmp/" + port + "/version", value:version );
  set_kb_item( name:"pfsense/snmp/" + port + "/concluded", value:sysdesc);
}

exit( 0 );
