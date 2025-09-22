# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113054");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-11-21 10:13:14 +0100 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("SSL/TLS: Known Untrusted / Dangerous Certificate Authority (CA) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"summary", value:"The service is using an SSL/TLS certificate from a known
  untrusted and/or dangerous certificate authority (CA).");

  script_tag(name:"impact", value:"An attacker could use this for man-in-the-middle (MITM) attacks,
  accessing sensible data and other attacks.");

  script_tag(name:"vuldetect", value:"The script reads the certificate used by the target host and
  checks if it was signed by a known untrusted and/or dangerous CA.");

  script_tag(name:"solution", value:"Replace the SSL/TLS certificate with one signed by a trusted
  CA.");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  # Contains the list of keys which are signed by an untrusted CA
  untrusted_keys = make_array();

  foreach key( keys( ssls ) ) {

    tmp   = split( key, sep:"/", keep:FALSE );
    port  = tmp[2];
    vhost = tmp[3];

    fprlist = get_kb_item( key );
    if( ! fprlist )
      continue;

    result = check_cert_validity( fprlist:fprlist, port:port, vhost:vhost, check_for:"untrusted_ca" );
    if( result )
      untrusted_keys[port] = result;
  }

  foreach port( keys( untrusted_keys ) ) {

    # nb:
    # - Store the reference from this one to gb_ssl_tls_cert_details.nasl to show a cross-reference
    #   within the reports
    # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
    register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103692" ); # gb_ssl_tls_cert_details.nasl
    register_host_detail( name:"detected_at", value:port + "/tcp" );

    info   = untrusted_keys[port];
    issuer = info[0];
    key    = info[1];
    url    = info[2];
    report = 'The certificate of the remote service is signed by the following untrusted and/or dangerous CA:\n\n';
    report += 'Issuer: ' + issuer + '\n';
    if( url && url != "none" )
      report += 'Reference: ' + url + '\n';
    report += cert_summary( key:key );
    security_message( data:report, port:port );
  }
  exit( 0 );
}

exit( 99 );
