# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103957");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-11-28 11:27:17 +0700 (Thu, 28 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Certificate Will Soon Expire");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_ssl_tls_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_xref(name:"URL", value:"https://letsencrypt.org/2015/11/09/why-90-days.html");

  script_tag(name:"insight", value:"This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any will expire during then next 28 days
  for the Let's Encrypt Certificate Authority or 60 days for any other Certificate Authority.");

  script_tag(name:"solution", value:"Prepare to replace the SSL/TLS certificate by a new one.");

  script_tag(name:"summary", value:"The remote server's SSL/TLS certificate will soon expire.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("list_array_func.inc");
include("host_details.inc");

#TBD: Make the lookahead and the overwrite for specific issuers configurable?

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  # Contains the list of keys which expires soon
  toexpire_keys = make_array();

  # Mapping between keys and used lookahead
  lookahead_keys = make_array();

  # The current time
  now = isotime_now();
  # isotime_now: "If the current time is not available an empty string is returned."
  if( strlen( now ) <= 0 )
    exit( 0 );

  foreach key( keys( ssls ) ) {

    tmp   = split( key, sep:"/", keep:FALSE );
    port  = tmp[2];
    vhost = tmp[3];

    if( ! fprlist = get_kb_item( key ) )
      continue;

    itmp = split( fprlist, sep:",", keep:FALSE );
    ifpr = itmp[0];
    ikey = "HostDetails/Cert/" + ifpr + "/";

    # How many days in advance to warn of certificate expiry.
    lookahead = 60;

    issuer = get_kb_item( ikey + "issuer" );

    # https://letsencrypt.org/2015/11/09/why-90-days.html
    # List of certificates and their O / CN fields can be found at:
    # https://letsencrypt.org/certificates/
    # The "issuer" content we're getting looks like e.g. the following:
    # CN=R3,O=Let's Encrypt,C=US
    if( "Let's Encrypt" >< issuer )
      lookahead = 28;

    # The current time plus lookahead
    future = isotime_add( now, days:lookahead );
    # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).
    if( isnull( future ) )
      continue;

    result = check_cert_validity( fprlist:fprlist, port:port, vhost:vhost, check_for:"expire_soon", now:now, timeframe:future );
    if( result ) {
      toexpire_keys[port]  = result;
      lookahead_keys[port] = lookahead;
    }
  }

  foreach port( keys( toexpire_keys ) ) {

    # nb:
    # - Store the reference from this one to gb_ssl_tls_cert_details.nasl to show a cross-reference
    #   within the reports
    # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
    register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103692" ); # gb_ssl_tls_cert_details.nasl
    register_host_detail( name:"detected_at", value:port + "/tcp" );

    report = "The certificate of the remote service will expire within the next " + lookahead_keys[port];
    report += " days on " + isotime_print( get_kb_item( toexpire_keys[port] + "notAfter" ) ) + '.\n';
    report += cert_summary( key:toexpire_keys[port] );
    log_message( data:report, port:port );
  }
  exit( 0 );
}

exit( 99 );
