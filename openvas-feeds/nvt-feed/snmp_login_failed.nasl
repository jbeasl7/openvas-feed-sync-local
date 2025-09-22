# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108541");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-24 09:05:25 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SNMP Login Failed For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("SNMP");
  script_dependencies("snmp_detect.nasl");
  script_mandatory_keys("login/SNMP/failed");

  script_tag(name:"summary", value:"It was NOT possible to login using the provided SNMPv1 /
  SNMPv2 community string / SNMPv3 credentials. Hence version checks based on SNMP might not work
  (if no other default community string was found).");

  script_tag(name:"solution", value:"Recheck the SNMPv1/SNMPv2 community string or SNMPv3 credentials
  as well as the output of the VT 'An SNMP Agent is running' (OID: 1.3.6.1.4.1.25623.1.0.10265).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "login/SNMP/failed/port" );
if( ! port )
  port = 0;

log_message( port:port, proto:"udp" );
exit( 0 );
