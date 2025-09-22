# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140096");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-12 12:33:00 +0100 (Mon, 12 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Checkmk Agent Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service5.nasl");
  script_require_ports("Services/checkmk_agent", 6556);

  script_tag(name:"summary", value:"Detection for Checkmk agent via the agent protocol.");

  script_xref(name:"URL", value:"https://docs.checkmk.com/latest/en/wato_monitoringagents.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");
include("os_func.inc");

SCRIPT_DESC = "Checkmk Agent Detection";
banner_type = "Check_MK AgentOS report";

if( ! port = service_get_port( default:6556, proto:"checkmk_agent" ) )
  exit( 0 );

if( ! banner = get_kb_item( "checkmk_agent/banner/" + port ) ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  banner = recv( socket:soc, length:2048 );
  close( soc );
  notinkb = TRUE;
}

if( "<<<check_mk>>>" >!< banner && "<<<uptime>>>" >!< banner && "<<<services>>>" >!< banner &&
    "<<<mem>>>" >!< banner )
  exit( 0 );

if( notinkb )
  replace_kb_item( name:"checkmk_agent/banner/" + port , value:banner );

version = "unknown";
location = "/";

set_kb_item( name:"checkmk/detected", value:TRUE );
set_kb_item( name:"checkmk/agent/detected", value:TRUE );

service_register( port:port, proto:"checkmk_agent" );

# Version: 1.5.0p12
vers = eregmatch( pattern:'Version: ([0-9.]+[^ \r\n]+)', string:banner );

if( ! isnull( vers[1] ) )
  version = vers[1];

extra = 'Gathered info (truncated):\n\n' + substr( banner, 0, 2000 ) + '\n[...]';

os = eregmatch( pattern:'AgentOS: ([a-zA-Z]+[^ \r\n]+)', string:banner );
if( os[1] ) {
  if( os[1] == "windows" ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type,
                            banner:os[0], port:port, desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( os[1] == "linux" ) {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:os[0],
                            port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( os[1] == "aix" ) {
    os_register_and_report( os:"IBM AIX", cpe:"cpe:/o:ibm:aix", banner_type:banner_type, banner:os[0],
                            port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    # nb: Setting the runs_key to unixoide makes sure that we still schedule VTs using Host/runs_unixoide as a fallback
    os_register_and_report( os:os[1], banner_type:banner_type, banner:os[0], port:port, desc:SCRIPT_DESC,
                            runs_key:"unixoide" );
    os_register_unknown_banner( banner:os[0], banner_type_name:banner_type,
                                banner_type_short:"checkmk_agent_banner", port:port );
  }
}

cpe = build_cpe( value:tolower( version ), exp:"^([0-9a-z.]+)", base:"cpe:/a:checkmk:checkmk:" );
if( ! cpe )
  cpe = "cpe:/a:checkmk:checkmk";

register_product( cpe:cpe, location:location, port:port, service:"checkmk_agent" );

report = build_detection_report( app:"Checkmk Agent", version:version, install:location, cpe:cpe,
                                 concluded:vers[0], extra:chomp( extra ) );
log_message( port:port, data:report );

exit( 0 );
