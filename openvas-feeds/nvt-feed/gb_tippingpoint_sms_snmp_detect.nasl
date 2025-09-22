# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108569");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-04-25 08:00:03 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Trend Micro TippingPoint Security Management System (SMS) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of a Trend Micro
  TippingPoint Security Management System (SMS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port( default:161 );
sysdesc = snmp_get_sysdescr( port:port );
if( ! sysdesc || sysdesc !~ "^SMS [^ ]+ v?SMS" )
  exit( 0 );

version = "unknown";

# SMS sms-server vSMS 5.0.0.106258.1
vers = eregmatch( pattern:"^SMS [^ ]+ v?SMS ([0-9.]+)", string:sysdesc );
if( vers[1] )
  version = vers[1];

set_kb_item( name:"tippingpoint/sms/detected", value:TRUE );
set_kb_item( name:"tippingpoint/sms/snmp/detected", value:TRUE );
set_kb_item( name:"tippingpoint/sms/snmp/port", value:port );
set_kb_item( name:"tippingpoint/sms/snmp/" + port + "/concluded", value:sysdesc );
set_kb_item( name:"tippingpoint/sms/snmp/" + port + "/version", value:version );

exit( 0 );
