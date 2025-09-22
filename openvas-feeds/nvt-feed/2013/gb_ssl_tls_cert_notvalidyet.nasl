# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103956");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-11-27 14:44:54 +0700 (Wed, 27 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Certificate Not Valid Yet");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_ssl_tls_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"insight", value:"This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any are not valid yet.");

  script_tag(name:"solution", value:"Replace the SSL/TLS certificate by a new one.");

  script_tag(name:"summary", value:"The remote server's SSL/TLS certificate is not valid yet.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("list_array_func.inc");
include("host_details.inc");

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  # The current time
  now = isotime_now();
  # isotime_now: "If the current time is not available an empty string is returned."
  if( strlen( now ) <= 0 )
    exit( 0 );

  # Contains the list of keys which are not valid yet
  notvalid_keys = make_array();

  foreach key( keys( ssls ) ) {

    tmp   = split( key, sep:"/", keep:FALSE );
    port  = tmp[2];
    vhost = tmp[3];

    if( ! fprlist = get_kb_item( key ) )
      continue;

    result = check_cert_validity( fprlist:fprlist, port:port, vhost:vhost, check_for:"not_valid_yet", now:now, timeframe:0 );
    if( result )
      notvalid_keys[port] = result;
  }

  foreach port( keys( notvalid_keys ) ) {

    # nb:
    # - Store the reference from this one to gb_ssl_tls_cert_details.nasl to show a cross-reference
    #   within the reports
    # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
    register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103692" ); # gb_ssl_tls_cert_details.nasl
    register_host_detail( name:"detected_at", value:port + "/tcp" );

    report = "The certificate of the remote service is not valid before ";
    report += isotime_print( get_kb_item( notvalid_keys[port] + "notBefore" ) ) + '.\n';
    report += cert_summary( key:notvalid_keys[port] );
    log_message( data:report, port:port );
  }
  exit( 0 );
}

exit( 99 );
