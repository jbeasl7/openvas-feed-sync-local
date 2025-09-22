# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108546");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-02-09 16:58:00 +0100 (Sat, 09 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OSSEC/Wazuh ossec-authd Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/unknown", 1515);

  script_xref(name:"URL", value:"https://www.ossec.net/");

  script_tag(name:"summary", value:"TCP based detection of a OSSEC/Wazuh ossec-authd service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

port = unknownservice_get_port( default:1515 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

# https://github.com/wazuh/wazuh/blob/5e71e413f6dc549e68dbc2bc16793c62d314cada/src/os_auth/main-client.c#L371-L417
# https://github.com/ossec/ossec-hids/blob/dd93bb0f1f2a58b9fcb19a22db4859b973a5277c/src/os_auth/main-client.c#L314-L329
req = "OSSEC A:'" + this_host_name() + "'" + '\n';
send( socket:soc, data:req );
buf = recv_line( socket:soc, length:512 );
close( soc );

# Examples:
# OSSEC K:'025 myhostname myip agentkey'
# -> https://github.com/wazuh/wazuh/blob/5e71e413f6dc549e68dbc2bc16793c62d314cada/src/os_auth/main-server.c#L1107
# OSSEC K:'agentkey'
# -> https://github.com/ossec/ossec-hids/blob/3951139adbdb33126de684f9172cc5b017f2f4f0/src/os_auth/main-server.c#L522
#
# nb: If password auth is enabled or the client needs to provide a valid cert we're not getting a response from the service.

if( ! buf || ( buf !~ "^OSSEC K:'.+'" && "ERROR: Unable to add agent." >!< buf ) )
  exit( 0 );

service_register( port:port, proto:"ossec-authd" );
set_kb_item( name:"ossec_wazuh/authd/detected", value:TRUE );
set_kb_item( name:"ossec_wazuh/authd/no_auth", value:TRUE );
set_kb_item( name:"ossec_wazuh/authd/" + port + "/detected", value:TRUE );
set_kb_item( name:"ossec_wazuh/authd/" + port + "/no_auth", value:TRUE );

log_message( port:port, data:"An ossec-authd service seems to be running on this port." );

# nb:
# - Store the reference from this one to some VTs like e.g. b_ossec-authd_unprotected.nasl using the
#   info collected here to show a cross-reference within the reports
# - We're not using register_product() here as we don't want to register the protocol within this
#   VT but just want to make use of the functionality to show the reference in the reports
# - If changing the syntax of e.g. the port + "/tcp" below make sure to update VTs like e.g. the
#   b_ossec-authd_unprotected.nasl accordingly
register_host_detail( name:"OSSEC/Wazuh ossec-authd Service Detection (TCP)", value:"cpe:/a:ossec:authd" );
register_host_detail( name:"cpe:/a:ossec:authd", value:port + "/tcp" );
register_host_detail( name:"port", value:port + "/tcp" );

exit( 0 );
