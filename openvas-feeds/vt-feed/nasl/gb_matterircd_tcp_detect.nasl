# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108460");
  script_version("2026-11-17T05:40:57+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2026-11-17 05:40:57 +0000 (Tue, 17 Nov 2026)");
  script_tag(name:"creation_date", value:"2018-09-14 12:41:10 +0200 (Fri, 14 Sep 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("matterircd Detection (IRC)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ircd_tcp_detect.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_tag(name:"summary", value:"IRC based detection of a matterircd server/daemon.");

  script_xref(name:"URL", value:"https://github.com/42wim/matterircd/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

port = service_get_port( default:6667, proto:"irc" );

banner = get_kb_item( "irc/banner/" + port );
if( ! banner || "matterircd" >!< banner )
  exit( 0 );

set_kb_item( name:"matterircd/detected", value:TRUE );
set_kb_item( name:"matterircd/irc/detected", value:TRUE );

install = port + "/tcp";
version = "unknown";

# :matterircd 002 BFBGHJCBJ :Your host is matterircd, running version 0.3
vers = eregmatch( pattern:"Your host is matterircd, running version ([0-9.]+)", string:banner );
if( vers[1] )
  version = vers[1];

cpe = build_cpe( value:version, exp:"^([0-9.]+[0-9])", base:"cpe:/a:42wim:matterircd:" );
if( ! cpe )
  cpe = "cpe:/a:42wim:matterircd";

register_product( cpe:cpe, location:install, port:port, service:"irc" );

log_message( data:build_detection_report( app:"matterircd",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:banner ),
             port:port );

exit( 0 );
