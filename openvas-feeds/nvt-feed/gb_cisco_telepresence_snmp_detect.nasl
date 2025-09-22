# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103890");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-01-27 13:32:54 +0100 (Mon, 27 Jan 2014)");
  script_name("Cisco TelePresence Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Cisco TelePresence.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if( !sysdesc || sysdesc !~ '(Cisco|TANDBERG) Codec' || "MCU:" >!< sysdesc || "SoftW:" >!< sysdesc ) exit (0);

typ = 'unknown';
version = 'unknown';

t = eregmatch( pattern:'MCU: ([^\r\n]+)', string:sysdesc );
if( ! isnull( t[1] ) )
  typ = t[1];

s = eregmatch( pattern:'SoftW: ([^\r\n]+)', string:sysdesc );
if( ! isnull( s[1] ) )
  version = s[1];

set_kb_item( name:"cisco/telepresence/typ", value:typ );
set_kb_item( name:"cisco/telepresence/version", value:version  );

cpe = 'cpe:/a:cisco:telepresence_mcu_mse_series_software:' + tolower ( version );

register_product( cpe:cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp");
log_message( data: build_detection_report( app: typ,
                                           version: version,
                                           install: port + "/udp",
                                           cpe: cpe,
                                           concluded:sysdesc ),
             port: port, proto: "udp" );

exit (0);
