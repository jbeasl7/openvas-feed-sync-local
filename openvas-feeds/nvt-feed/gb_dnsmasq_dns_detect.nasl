# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100266");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-09-01 22:29:29 +0200 (Tue, 01 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dnsmasq Detection (DNS)");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("dns_server_tcp.nasl", "dns_server.nasl");
  script_mandatory_keys("dns/server/detected");

  script_tag(name:"summary", value:"DNS based detection of Dnsmasq.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

function getVersion( data, port, proto ) {

  local_var data, port, proto;
  local_var version, ver;

  if( ! data || "dnsmasq" >!< tolower( data ) )
    return;

  version = "unknown";

  # dnsmasq-pi-hole-2.79
  # dnsmasq-2.76
  # dnsmasq-pi-hole-2.87test3
  # dnsmasq-pi-hole-2.87test4-6
  # dnsmasq-pi-hole-v2.87rc1
  # dnsmasq-pi-hole-v2.89-9461807
  # dnsmasq-pi-hole-v2.90
  # dnsmasq-pi-hole-v2.90+1
  # dnsmasq-2.78-23-g9e09429
  # dnsmasq-pi-hole-v2.92test11
  # dnsmasq-UNKNOWN
  ver = eregmatch( pattern:"dnsmasq-(pi-hole-)?v?([0-9.]+((rc|test)[0-9-]+)?)", string:data, icase:TRUE );
  if( ver[2] )
    version = ver[2];

  set_kb_item( name:"thekelleys/dnsmasq/detected", value:TRUE );
  set_kb_item( name:"thekelleys/dnsmasq/dns-" + proto + "/detected", value:TRUE );
  set_kb_item( name:"thekelleys/dnsmasq/dns-" + proto + "/" + port + "/installs", value:port + "#---#" + port + "/" + proto + "#---#" + version + "#---#" + data );
}

udp_ports = get_kb_list( "DNS/udp/version_request" );
foreach port( udp_ports ) {

  data = get_kb_item( "DNS/udp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"udp" );
}

tcp_ports = get_kb_list( "DNS/tcp/version_request" );
foreach port( tcp_ports ) {

  data = get_kb_item( "DNS/tcp/version_request/" + port );
  if( ! data )
    continue;

  getVersion( data:data, port:port, proto:"tcp" );
}

exit( 0 );
