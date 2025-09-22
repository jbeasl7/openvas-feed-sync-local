# SPDX-FileCopyrightText: 2009 Tim Brown
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100950");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-10 19:42:14 +0200 (Fri, 10 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft DNS Server Internal Hostname Disclosure Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Tim Brown");
  script_dependencies("dns_server.nasl");
  script_require_udp_ports("Services/udp/domain", 53);
  script_mandatory_keys("dns/server/udp/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20140419113733/http://support.microsoft.com/kb/198410");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/blog.php?id=31");

  script_tag(name:"summary", value:"Microsoft DNS server might be prone to an internal hostname
  disclosure.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted DNS requests to the 0.in-addr.arpa and
  255.in-addr.arpa zones and checks the responses.");

  script_tag(name:"insight", value:"Microsoft DNS server may disclose the internal hostname of the
  server in response to requests for the hardcoded zones 0.in-addr.arpa and 255.in-addr.arpa.");

  script_tag(name:"affected", value:"Microsoft DNS server is known to be affected. Other DNS servers
  / configurations might be affected as well.");

  script_tag(name:"solution", value:"On the following platforms, we recommend you resolve in the
  described manner:

  - All default Microsoft DNS server configurations: Please see the referenced KB article KB198410

  - Other DNS servers / configurations: Please contact the vendor for more information");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("port_service_func.inc");

function packet_construct( _dns_zone ) {

  local_var _dns_zone;
  local_var _dns_query;

  # query _dns_zone/SOA/IN
  _dns_query = raw_string( 0x8d, 0x31, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  foreach _dns_node( split( _dns_zone, sep:".", keep:FALSE ) ) {
    _dns_query += raw_string( strlen( _dns_node ) ) + _dns_node;
  }
  _dns_query += raw_string( 0x00, 0x00, 0x06, 0x00, 0x01 );
  return _dns_query;
}

function packet_parse( _dns_query, _dns_response, port ) {

  local_var _dns_query, _dns_response, port;
  local_var _hostdata, _hostname, _counter1, _counter2, report;

  if( isnull( _dns_response ) )
    return;

  # for a valid SOA response:
  # TXID 2
  # Flags 2 - 2 is server failure, 3 is no such name and 5 is refused
  # Questions 2
  # Answers 2
  # Authority 2
  # Additional 2
  # DNS query x + 2 (length encoded, with null)
  # Type 2
  # Class 2
  # Name 2
  # Type 2
  # Class 2
  # TTL 4
  # Data length 2
  # DNS server x + 2 (length encoded, with null)
  # Email address x + 3 (length encoded with 2 trailing bytes?)
  # Serial 4
  # Refresh interval 4
  # Retry interval
  # Expiry limit
  # Minimum TTL
  # nb: is it a valid response?
  if( ( _dns_response != "" ) && ( ( ord( _dns_response[3] ) & 2 ) != 2 ) && ( ( ord( _dns_response[3] ) & 3 ) != 3 ) && ( ( ord( _dns_response[3] ) & 5 ) != 5 ) ) {
    _hostdata = substr( _dns_response, 12 + strlen( _dns_query ) + 18 );
    _hostname = "";

    if( strlen( _hostdata ) < 2 )
      return;

    # nb: is it using DNS compression with a pointer offset to the DNS query?
    if( ( ord( _hostdata[0] ) != 192 ) && ( ord( _hostdata[1] ) != 12 ) ) {
      _counter1 = 0;
      while( ord( _hostdata[_counter1] ) != 0 ) {

        for( _counter2 = 1; _counter2 <= ord( _hostdata[_counter1] ); _counter2++ ) {
          _hostname += _hostdata[_counter1 + _counter2];
        }

        _counter1 += _counter2;
        if( ord( _hostdata[_counter1] ) != 0 ) {
          _hostname += ".";
        }
      }

      if( strlen( _hostname ) < 0 )
        return;

      if( "localhost" >< _hostname )
        return;

      # nb:
      # - 0.IN-ADDR.ARPA has been also seen as a possible result on "live" targets which is also not
      #   a valid internal hostname
      # - We're also including the sent DNS query in case it is getting returned to us for some
      #   unknown reason
      # - A return of just "arpa" has been also seen recently on some "live" targets which is
      #   definitely not an internal hostname in all cases
      if( tolower( _hostname ) == "0.in-addr.arpa" ||
          tolower( _hostname ) == "arpa" ||
          tolower( _hostname ) == _dns_query )
        return;

      report = "The following internal hostname was disclosed (Extracted via " + _dns_query + "/SOA/IN): " + _hostname;
      log_message( proto:"udp", port:port, data:report );
      set_kb_item( name:"DNS/udp/" + port + "/hostname", value:_hostname );
      exit( 0 );
    }
  }
}

port = service_get_port( default:53, proto:"domain", ipproto:"udp" );

foreach dns_zone( make_list( "0.in-addr.arpa", "255.in-addr.arpa" ) ) {

  if( ! soc = open_sock_udp( port ) )
    continue;

  req = packet_construct( _dns_zone:dns_zone );
  send( socket:soc, data:req );
  res = recv( socket:soc, length:4096 );
  close( soc );
  packet_parse( _dns_query:dns_zone, _dns_response:res, port:port );
}

exit( 99 );
