# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108301");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-11-29 08:03:31 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lantronix Devices Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Lantronix Devices.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );
if( ! sysdesc = snmp_get_sysdescr( port:port ) ) exit ( 0 );

# e.g. Lantronix UDS1100 V6.5.0.0 (070402)
# Lantronix SLSLP 030020
# Lantronix MSSLITE Version V3.6/4(000628)
# Lantronix UDS 1325732 V5.8.0.1 (041112)
# Lantronix UDS2100 V6.7.0.3 (110711)
# Lantronix MSS-VIA Version V3.6/3(000201)
# Lantronix MSS4 Version B3.7/108(030909)
# Lantronix SCS1600 Version 2.0/5(040701)
if( sysdesc =~ "^Lantronix" ) {

  set_kb_item( name:"lantronix_device/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/snmp/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/snmp/port", value:port );

  version = "unknown";
  type    = "unknown";
  vers_nd_type = eregmatch( pattern:"^Lantronix ([A-Z0-9-]+) .*(V|B|Version )([0-9.]+)", string:sysdesc, icase:FALSE );
  if( vers_nd_type[1] ) type    = vers_nd_type[1];
  if( vers_nd_type[3] ) version = vers_nd_type[3];

  set_kb_item( name:"lantronix_device/snmp/" + port + "/type", value:type );
  set_kb_item( name:"lantronix_device/snmp/" + port + "/version", value:version );
  set_kb_item( name:"lantronix_device/snmp/" + port + "/concluded", value:sysdesc);
}

exit( 0 );
