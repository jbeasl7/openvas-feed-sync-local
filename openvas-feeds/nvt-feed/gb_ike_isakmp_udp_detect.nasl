# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117461");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2021-05-28 11:07:40 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IKE / ISAKMP Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_dependencies("gb_open_udp_ports.nasl", "echo_udp.nasl");
  # nb: 4500/udp is NAT-T IKE (RFC 3947 NAT-Traversal encapsulation)
  script_require_udp_ports("Services/udp/unknown", 500, 4500);

  script_tag(name:"summary", value:"UDP based detection of services supporting the Internet Key
  Exchange (IKE) Protocol / Internet Security Association and Key Management Protocol (ISAKMP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("ike_isakmp_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("byte_func.inc");
include("list_array_func.inc");
include("pcap_func.inc");
include("version_func.inc");
include("dump.inc");

debug = FALSE;
proto = "udp";
ports = unknownservice_get_ports( default_port_list:make_list( 500, 4500 ), ipproto:proto );

foreach port( ports ) {

  # nb: As the service detection below depends on the service responding with our initiator SPI
  # this should make sure that we're not doing any false reporting against UDP echo services.
  if( get_kb_item( "echo_udp/" + port + "/detected" ) )
    continue;

  # nb: See comment in isakmp_create_transforms_packet_from_list()
  foreach used_list( make_list( "short_transforms_list", "full_transforms_list" ) ) {

    if( used_list == "full_transforms_list" ) {
      # nb: Need to wait a few seconds as some tested services didn't respond on subsequent
      # requests in a short amount of time.
      sleep( 10 );
    }

    if( used_list == "short_transforms_list" )
      use_short_transforms_list = TRUE;
    else
      use_short_transforms_list = FALSE;

    transforms_info = isakmp_create_transforms_packet_from_list( enable_short_list:use_short_transforms_list );
    if( ! transforms_info )
      continue;

    transforms = transforms_info[0];
    transforms_num = transforms_info[1];
    my_initiator_spi = rand_str( length:8, charset:"abcdefghiklmnopqrstuvwxyz0123456789" );

    req = isakmp_create_request_packet( port:port, ipproto:proto, exchange_type:"Identity Protection (Main Mode)", transforms:transforms, transforms_num:transforms_num, initiator_spi:my_initiator_spi );
    if( ! req )
      continue;

    # nb: We currently can only use the pcap functionality for the short_transforms_list because
    # of a too large UDP data size in the crafted IP/UDP packet which probably would need automatic
    # fragmentation support in either send_packet() of the scanner or pcap_tcp_udp_send_recv() of
    # pcap_func.inc.
    if( use_short_transforms_list ) {
      res = isakmp_send_recv( port:port, data:req, initiator_spi:my_initiator_spi, proto:proto, use_pcap:TRUE, debug:debug );
    } else {
      if( ! soc = isakmp_open_socket( port:port, proto:proto ) )
        continue;

      res = isakmp_send_recv( soc:soc, data:req, initiator_spi:my_initiator_spi, proto:proto, use_pcap:FALSE, debug:debug );
      close( soc );
    }

    # nb: isakmp_send_recv is internally already checking various things like a matching Initiator
    # SPI of the response, the packet length, a valid KE/ISAKMP version and similar and is returning
    # NULL if unexpected / invalid data is received. This means we don't need any extra checks here.
    if( ! res )
      continue;

    # nb: For NAT-T we might / should get a "Non-ESP Marker", see the following RFC for more info:
    # https://www.rfc-editor.org/rfc/rfc3948
    # This is already tested / verified in isakmp_send_recv() but we need to handle this here as
    # well so that we can extract the correct IKE version later
    offset = 0;
    if( hexstr( substr( res, 0, 3 ) ) == "00000000" )
      offset = 4;

    # Includes the major (e.g. 1) and the minor version (e.g. 0).
    # nb: Shouldn't be empty / FALSE / NULL but still checking just to be sure...
    ike_vers = res[17 + offset];
    if( ! ike_vers )
      continue;

    # nb: From ike_isakmp_func.inc. Currently supported: 1.0 and 2.0.
    ike_vers_text = VERSIONS[ike_vers];
    if( ! ike_vers_text )
      continue;

    # nb for the register_product() calls:
    # - We can register a more generic CPE for the protocol itself which can be used for e.g.:
    #   - CVE scans / the CVE scanner
    #   - storing the reference from this one to some VTs like e.g. gb_ike_CVE-2002-1623.nasl using
    #     the info collected here to show a cross-reference within the reports
    # - If changing the syntax of e.g. the "location" below make sure to update VTs like e.g. the
    #   gb_ike_CVE-2002-1623.nasl accordingly

    if( ike_vers_text == "1.0" ) {
      set_kb_item( name:"isakmp/v1.0/detected", value:TRUE );
      set_kb_item( name:"isakmp/v1.0/" + proto + "/detected", value:TRUE );
      set_kb_item( name:"isakmp/v1.0/" + proto + "/" + port + "/detected", value:TRUE );

      register_product( cpe:"cpe:/a:ietf:internet_key_exchange:1.0", location:port + "/udp", port:port, proto:"udp", service:"isakmp" );

    } else if( ike_vers_text == "2.0" ) {
      set_kb_item( name:"isakmp/v2.0/detected", value:TRUE );
      set_kb_item( name:"isakmp/v2.0/" + proto + "/detected", value:TRUE );
      set_kb_item( name:"isakmp/v2.0/" + proto + "/" + port + "/detected", value:TRUE );

      register_product( cpe:"cpe:/a:ietf:internet_key_exchange:2.0", location:port + "/udp", port:port, proto:"udp", service:"isakmp" );
    }

    if( used_list == "full_transforms_list" )
      set_kb_item( name:"isakmp/" + proto + "/" + port + "/full_transforms_list_required", value:TRUE );
    else
      set_kb_item( name:"isakmp/" + proto + "/" + port + "/short_transforms_list_used", value:TRUE );

    set_kb_item( name:"ike/detected", value:TRUE );
    set_kb_item( name:"ike/udp/detected", value:TRUE );

    service_register( port:port, ipproto:proto, proto:"isakmp" );

    log_message( port:port, proto:proto, data:"A service supporting the IKE/ISAKMP protocol is running at this port." );

    break; # Stop if the initial "short_transforms_list" based request was successful.
  }
}

exit( 0 );
