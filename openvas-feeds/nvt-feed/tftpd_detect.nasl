# SPDX-FileCopyrightText: 2009 Vlatko Kosturjak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80100");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-03-04 10:25:48 +0100 (Wed, 04 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_copyright("Copyright (C) 2009 Vlatko Kosturjak");
  script_name("TFTP Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_require_udp_ports(69);

  script_tag(name:"solution", value:"Disable TFTP server if not used.");

  script_tag(name:"summary", value:"The remote host has a TFTP server running. TFTP stands
  for Trivial File Transfer Protocol.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("tftp.inc");
include("version_func.inc");
include("misc_func.inc");

foundtftp = FALSE;

# taken from tftpd_dir_trav.nasl, adapted a bit
function tftp_grab( port, file, mode ) {

  local_var req, rep, sport, ip, u, filter, data, i;

  req = '\x00\x01' + file + '\0' + mode + '\0';

  sport = rand() % 64512 + 1024;

  if( TARGET_IS_IPV6() ) {

    # nb: Previous versions had calculated a wrong IPv6 flow label
    # (see https://github.com/greenbone/openvas/pull/545) which
    # requires this workaround here.
    # TODO: Remove once all GOS/GVM versions < 20.8.0 are EOL.
    if( version_is_less( version:OPENVAS_VERSION, test_version:"20.8.0" ) )
      IP6_v = 0x60;
    else
      IP6_v = 6;

    IP6_P = IPPROTO_UDP;
    IP6_HLIM = 0x40;
    # TODO: Use forge_ip_v6_packet once all GOS/GVM versions < 20.8.0 are EOL.
    ip6_packet = forge_ipv6_packet( ip6_v:IP6_v,
                                    ip6_p:IP6_P,
                                    ip6_plen:20,
                                    ip6_hlim:IP6_HLIM,
                                    ip6_src:this_host(),
                                    ip6_dst:get_host_ip() );

    udppacket = forge_udp_v6_packet( ip6:ip6_packet,
                                     uh_sport:sport,
                                     uh_dport:port,
                                     uh_ulen:8 + strlen( req ),
                                     data:req );

    filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and dst host ' + this_host();

    for( i = 0; i < 2; i++ ) { # Try twice

      rpkt = send_v6packet( udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1 );
      if( ! rpkt ) continue;

      data = get_udp_v6_element( udp:rpkt, element:"data" );
      if( isnull( data ) || strlen( data ) < 2 ) continue;

      if( data[0] == '\0' ) {
        if( data[1] == '\x03' || data[1] =='\x05' ) {
          foundtftp = TRUE;
          break;
        }
      }
    }
  } else {

    ip = forge_ip_packet( ip_hl:5,
                          ip_v:4,
                          ip_tos:0,
                          ip_len:20,
                          ip_off:0,
                          ip_ttl:64,
                          ip_p:IPPROTO_UDP,
                          ip_src:this_host() );

    u = forge_udp_packet( ip:ip,
                          uh_sport:sport,
                          uh_dport:port,
                          uh_ulen:8 + strlen( req ),
                          data:req );

    filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

    data = NULL;
    for( i = 0; i < 2; i ++ ) { # Try twice

      rep = send_packet( u, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1 );
      if( ! rep ) continue;

      data = get_udp_element( udp:rep, element:"data" );
      if( isnull( data ) || strlen( data ) < 2 ) continue;

      if( data[0] == '\0' ) {
        if( data[1] == '\x03' || data[1] =='\x05' ) {
          foundtftp = TRUE;
          break;
        }
      }
    }

    # safeguard against some random/broken responses
    if( foundtftp ) {
      if( tftp_get( port:port, path:rand_str( length:10 ) ) )
        set_kb_item( name:"tftp/" + port + "/rand_file_response", value:TRUE );
    }
  }
}

port = service_get_port( default:69, proto:"tftp", ipproto:"udp" );

rndfile = "nonexistant-" + rand_str();

# test valid modes according to RFC-783
tftp_grab( port:port, file:rndfile, mode:"netascii" );

if( ! foundtftp ) {
  tftp_grab( port:port, file:rndfile, mode:"octet" );
}

if( ! foundtftp ) {
  tftp_grab( port:port, file:rndfile, mode:"mail" );
}

if( foundtftp ) {
  service_register( port:port, ipproto:"udp", proto:"tftp" );
  log_message( port:port, proto:"udp" );
  set_kb_item( name:"tftp/detected", value:TRUE );
}

exit( 0 );
