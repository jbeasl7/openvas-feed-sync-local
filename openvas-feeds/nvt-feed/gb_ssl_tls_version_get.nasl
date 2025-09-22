# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105782");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-06-29 10:54:20 +0200 (Wed, 29 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("secpod_open_tcp_ports.nasl", "gb_starttls_pop3.nasl", "gb_starttls_imap.nasl",
                      "gb_starttls_ftp.nasl", "gb_starttls_smtp.nasl", "gb_postgresql_tls_support.nasl",
                      "gb_starttls_ldap.nasl", "gb_starttls_nntp.nasl", "gb_starttls_xmpp.nasl",
                      "gb_starttls_mysql.nasl", "gb_starttls_irc.nasl", "gb_starttls_rdp.nasl",
                      "gb_dont_scan_fragile_device.nasl");
  script_mandatory_keys("TCP/PORTS");

  script_add_preference(name:"Seconds to wait between probes", value:"", type:"entry", id:1);

  script_tag(name:"summary", value:"Enumeration and reporting of SSL/TLS protocol versions supported
  by a remote service.");

  script_tag(name:"vuldetect", value:"Sends multiple connection requests to the remote service and
  attempts to determine the SSL/TLS protocol versions supported by the service from the replies.

  Note: The supported SSL/TLS protocol versions included in the report of this VT are reported
  independently from the allowed / supported SSL/TLS ciphers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("mysql.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

function get_tls_hello_record( vers, port, use_extended_ec, delay ) {

  local_var vers, port, use_extended_ec, delay;
  local_var soc, hello, data, search, record;

  if( ! vers || ! port )
    return;

  if( ! soc = open_ssl_socket( port:port ) )
    return;

  if( ! hello = ssl_hello( port:port, version:vers, use_extended_ec:use_extended_ec ) ) {
    close( soc );
    return;
  }

  if( delay )
    sleep( delay );
  else
    usleep( 50000 );

  send( socket:soc, data:hello );
  data = ssl_recv( socket:soc );
  close( soc );
  if( ! data )
    return;

  if( vers == SSL_v2 )
    search = make_array( "content_typ", SSLv2_SERVER_HELLO );
  else if( vers == TLS_13 )
    search = make_array( "supported_versions", TLS_13 );
  else
    search = make_array( "handshake_typ", SSLv3_SERVER_HELLO );

  if( ! record = search_ssl_record( data:data, search:search ) ) {

    # For SSLv2 we're returning directly when not receiving an SERVER_HELLO.
    if( vers == SSL_v2 )
      return;

    # For all other versions we're checking if we have received an SSLv3_ALERT so
    # that our VT can check e.g. with an extended set of elliptic curves again.
    # This also saves a few requests against Non-TLS services for such cases because
    # we're only sending the additional requests if received such an SSLv3_ALERT.
    if( search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) ) )
      return "alert_received";
    else
      return;

  } else {
    return record;
  }
}

# nb: Don't use tcp_get_all_port() as we only want to exclude
# specific ports from the TLS checks defined in gb_dont_scan_fragile_device.nasl
port = get_kb_item( "TCP/PORTS" );
if( ! port || ! get_port_state( port ) )
  exit( 0 );

# nb: Set by gb_dont_scan_fragile_device.nasl. Some devices are even crashing
# if we're touching one or more ports of them with our SSL/TLS checks so those
# ports gets excluded here.
if( get_kb_item( "fragile_port/exclude_tls/" + port ) )
  exit( 0 );

d = script_get_preference( "Seconds to wait between probes", id:1 );
if( int( d ) > 0 )
  delay = int( d );

sup_tls = ""; # nb: To make openvas-nasl-lint happy...
# nb: Used later for doing the reporting
sup_tls_list = make_list();

foreach vers( make_list( TLS_10, TLS_11, TLS_12, TLS_13, SSL_v2, SSL_v3 ) ) {
  extended_ec_used = "no";

  record = get_tls_hello_record( vers:vers, port:port, use_extended_ec:FALSE, delay:delay );

  if( ! record || ( ! is_array( record ) && record == "alert_received" ) ) {

    # nb: Try with an extended set of "elliptic curves" (see _ssl3_tls_hello and
    # add_ssl_extension of ssl_funcs.inc). This isn't added in the first request
    # for backwards compatibility reasons (e.g. a system might throw an SSL Alert
    # if unsupported elliptic curves are requested / included in the Client Hello.
    # We're only requesting this for TLS 1.0 to 1.2. TLS 1.3 does not support
    # the "elliptic curves" extension any more and has mandatory support for
    # a "supported groups" extension with the same codepoint instead.
    if( vers == TLS_10 || vers == TLS_11 || vers == TLS_12 ) {
      record = get_tls_hello_record( vers:vers, port:port, use_extended_ec:TRUE, delay:delay );
      extended_ec_used = "yes";
    }

    if( ! record || ( ! is_array( record ) && record == "alert_received" ) )
      continue;
  }

  # nb: Ignore SSLv2 without ciphers
  if( vers == SSL_v2 && int( record["cipher_spec_len"] ) < 1 )
    continue;

  if( isnull( record["version"] ) )
    continue;

  if( record["version"] == vers ) {
    set_kb_item( name:"tls_version_get/" + port + "/version", value:version_string[vers] );
    set_kb_item( name:"tls_version_get/" + port + "/hex_version", value:hexstr( record["version"] ) );
    set_kb_item( name:"tls_version_get/" + port + "/raw_version", value:record["version"] );
    set_kb_item( name:"tls_version_get/" + port + "/extended_ec_used", value:extended_ec_used );
    set_kb_item( name:"tls_version_get/" + port + "/" + version_kb_string_mapping[vers] + "/extended_ec_used", value:extended_ec_used );
    sup_tls += version_string[vers] + ";";
    sup_tls_list = make_list( sup_tls_list, version_string[vers] );

    # nb:
    # - We can register a more generic CPE for the protocol itself which can be used for e.g.:
    #   - CVE scans / the CVE scanner
    #   - storing the reference from this one to some VTs like e.g. gb_tlsv10_v11_detect.nasl using
    #     the info collected here to show a cross-reference within the reports
    # - We're not using a 'service:""' call below for now as the service is not known yet
    # - If changing the syntax of e.g. the "location" below make sure to update VTs like e.g. the
    #   gb_tlsv10_v11_detect.nasl accordingly
    if( vers == TLS_10 )
      register_product( cpe:"cpe:/a:ietf:transport_layer_security:1.0", location:port + "/tcp", port:port );

    if( vers == TLS_11 )
      register_product( cpe:"cpe:/a:ietf:transport_layer_security:1.1", location:port + "/tcp", port:port );

    if( vers == TLS_12 )
      register_product( cpe:"cpe:/a:ietf:transport_layer_security:1.2", location:port + "/tcp", port:port );

    if( vers == TLS_13 )
      register_product( cpe:"cpe:/a:ietf:transport_layer_security:1.3", location:port + "/tcp", port:port );

    if( vers == SSL_v2 )
      register_product( cpe:"cpe:/a:ietf:secure_sockets_layer:2.0", location:port + "/tcp", port:port );

    if( vers == SSL_v3 )
      register_product( cpe:"cpe:/a:ietf:secure_sockets_layer:3.0", location:port + "/tcp", port:port );
  }
}

if( strlen( sup_tls ) ) {
  sup_tls = ereg_replace( string:sup_tls, pattern:"(;)$", replace:"" );
  set_kb_item( name:"tls/supported/" + port, value:sup_tls );
  set_kb_item( name:"ssl_tls/port", value:port );

  # nb: As SSLv3 and SSLv2 are tested after TLS1.0+ (this is expected) we're sorting the list first
  # to have SSLv2, SSLv3 and then TLS1.0+ reported afterwards.
  sup_tls_list = sort( sup_tls_list );
  foreach sup_tls_item( sup_tls_list )
    report += '\n' + sup_tls_item;

  if( strlen( report ) > 0 ) {
    report = 'The remote SSL/TLS service supports the following SSL/TLS protocol version(s):\n' + report;
    log_message( port:port, data:report );
  }
}

exit( 0 );
