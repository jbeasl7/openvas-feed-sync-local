# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113661");
  script_version("2024-11-28T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-28 05:05:41 +0000 (Thu, 28 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-03-30 14:14:14 +0100 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("wowza_streaming_engine/banner");

  script_tag(name:"summary", value:"HTTP based detection of Wowza Streaming Engine.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default: 1935 );

banner = http_get_remote_headers( port: port );

if( banner =~ "Server\s*:\s*WowzaStreamingEngine" ) {
  version = "unknown";

  set_kb_item( name: "wowza_streaming_engine/detected", value: TRUE );
  set_kb_item( name: "wowza_streaming_engine/http/detected", value: TRUE );
  set_kb_item( name: "wowza_streaming_engine/http/port", value: port );

  # Server: WowzaStreamingEngine/4.8.0
  # Server: WowzaStreamingEngine/4.8.20+1
  # Server: WowzaStreamingEngine/4.7.7.01
  vers = eregmatch( string: banner, pattern: "[Ss]erver\s*:\s*WowzaStreamingEngine/([0-9.+]+)" );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name: "wowza_streaming_engine/http/" + port + "/concluded", value: vers[0] );
  }

  set_kb_item( name: "wowza_streaming_engine/http/" + port + "/version", value: version );
}

exit( 0 );
