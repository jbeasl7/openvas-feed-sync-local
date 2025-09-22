# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100403");
  script_version("2023-07-28T16:09:08+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ZABBIX Server/Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service4.nasl");
  script_require_ports("Services/zabbix", 10050, 10051);

  script_tag(name:"summary", value:"Detection of a ZABBIX Server/Agent.

  The script sends a connection request to the server and attempts to
  identify the service from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

# https://www.zabbix.org/wiki/Docs/protocols/zabbix_agent/2.0#Active_agents
reqs = make_list( "ZBX_GET_HISTORY_LAST_ID", # Old agent request
                  '{"request":"active checks","host":"' + get_host_name() + '"}' ); # Zabbix is not responding on the above request on newer versions

ports = service_get_ports( default_port_list:make_list( 10050, 10051 ), proto:"zabbix" );
foreach port( ports ) {
  foreach req( reqs ) {

    soc = open_sock_tcp( port );
    if( ! soc ) break;

    send( socket:soc, data:req );

    buf = recv( socket:soc, length:1024 );
    close( soc );
    if( isnull( buf ) ) continue;

    # examples for different versions (nb: There are non-ascii chars after ZBXD)
    # ZBXD       ZBX_NOTSUPPORTED Unsupported item key.
    # ZBXD       {"response":"failed","info":"host [192.168.56.99] not found"}
    # ZBXD       ZBX_NOTSUPPORTED
    # ZBXD       FAIL
    if( buf =~ "^ZBXD" ) {

      service_register( port:port, proto:"zabbix" );
      set_kb_item( name:"Zabbix/installed", value:TRUE );
      set_kb_item( name:"Zabbix/AgentServer/installed", value:TRUE );
      install = port + "/tcp";
      version = "unknown";
      cpe = "cpe:/a:zabbix:zabbix";

      register_product( cpe:cpe, location:install, port:port, service:"zabbix" );

      log_message( data:build_detection_report( app:"Zabbix Server/Agent",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:buf ),
                                                port:port );
      break; # break out of the "foreach req" and continue with the next port
    }
  }
}

exit( 0 );
