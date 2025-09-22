# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103823");
  script_version("2024-09-30T08:38:05+0000");
  script_tag(name:"last_modification", value:"2024-09-30 08:38:05 +0000 (Mon, 30 Sep 2024)");
  script_tag(name:"creation_date", value:"2013-10-29 12:36:43 +0100 (Tue, 29 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Version Detection Report");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_add_preference(name:"Report TLS version", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"Collects and (if enabled) reports the detected SSL/TLS protocol
  versions (and additional information) in a comma separated and structured way.");

  script_tag(name:"insight", value:"The following information is collected and reported:

  - IP

  - Host

  - Port

  - SSL/TLS protocol version

  - Supported SSL/TLS ciphers

  - Application-CPE");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssl_funcs.inc");
include("host_details.inc");
include("byte_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

function get_tls_app( port ) {

  local_var port;
  local_var host_details, host_detail, host_values, oid, ports, p, cpe_str;

  if( ! host_details = get_kb_list( "HostDetails/NVT/*" ) )
    return;

  foreach host_detail( keys( host_details ) ) {

    if( "cpe:/" >< host_detail ) {

      host_values = split( host_detail, sep:"/", keep:FALSE );
      if( isnull( host_values[2] ) )
        continue;

      oid = host_values[2];

      ports = get_kb_list( "HostDetails/NVT/" + oid + "/port" ); # don't use get_kb_item(), because this could fork.
      if( ! ports )
        continue;

      foreach p( ports ) {
        if( p == port ) {
          if( host_values[4] >!< cpe_str ) {
            cpe_str += "cpe:/" +  host_values[4] + ";";
          }
        }
      }
    }
  }

  if( strlen( cpe_str ) ) {
    # Remove ending ";"
    cpe_str = ereg_replace( string:cpe_str, pattern:"(;)$", replace:"" );
    return cpe_str;
  }
}

function get_port_ciphers( port ) {

  local_var port;
  local_var ciphers, ret_ciphers, cipher;

  if( ! port )
    return;

  if( ! ciphers = get_kb_list( "ssl_tls/ciphers/*/" + port + "/supported_ciphers" ) )
    return;

  ret_ciphers = "";

  # Make unique and sort to not report changes on delta reports if just the order is different
  ciphers = make_list_unique( ciphers );
  ciphers = sort( ciphers );

  foreach cipher( ciphers ) {
    ret_ciphers += cipher + ";";
  }

  # Remove ending ";"
  ret_ciphers = ereg_replace( string:ret_ciphers, pattern:"(;)$", replace:"" );

  return ret_ciphers;

}

enable_log = script_get_preference( "Report TLS version", id:1 );

if( ! ports = tls_ssl_get_ports() )
  exit( 0 );

foreach port( ports ) {

  sup_tls = "";
  cpe = "";

  if( ! versions = get_kb_list( "tls_version_get/" + port + "/version" ) )
    continue;

  foreach vers( versions ) {
    set_kb_item( name:"tls_version/" + port + "/version", value:vers );
    sup_tls += vers + ";";
    register_host_detail( name:"TLS/port", value:port, desc:"SSL/TLS: Version Detection Report" );
    register_host_detail( name:"TLS/" + port, value:vers, desc:"SSL/TLS: Version Detection Report" );
  }

  if( strlen( sup_tls ) ) {
    # Remove ending ";"
    sup_tls = ereg_replace( string:sup_tls, pattern:"(;)$", replace:"" );
    supported_tls[port] = sup_tls;
  }
}

if( "yes" >!< enable_log )
  exit( 0 );

if( supported_tls ) {

  host = get_host_name();
  ip = get_host_ip();
  #TBD: Report ciphers for each SSL/TLS Version separately?
  text = 'IP,Host,Port,SSL/TLS-Version,Ciphers,Application-CPE\n';

  foreach p( keys( supported_tls ) ) {

    text += ip + "," + host + "," +  p + "," + supported_tls[p];

    ciphers = get_port_ciphers( port:p );
    if( ciphers )
      text += "," + ciphers;

    cpe = get_tls_app( port:p );

    if( cpe )
      text += "," + cpe + '\n';
    else
      text += '\n';

    text = ereg_replace( string:text, pattern:'\n\n', replace:'\n' );

    report = TRUE;
  }

  if( report ) {
    log_message( port:0, data:text );
    exit( 0 );
  }
}

exit( 0 );
