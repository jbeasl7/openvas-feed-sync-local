# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

##
# This is a list of KB entries created by this script. To avoid storing certificate details over and
# over again we use the SHA-256 fingerprint of a certificate as the unique identifier. The reason we
# do not use SHA-1 here is that we expect to see SHA-1 collisions for valid X.509 certificates in
# the not too far future. GVM should be able to single those attacks out. It is easier to use
# SHA-256 right now, than to switch to it later.
#
# The following keys are all prefixed with:
#   HostDetails/Cert/<sha-256-fingerprint>
#
# /type      => The type of the certificate; always: "X.509"
# /serial    => Serial number as hex string
# /issuer    => Issuer as rfc2253 string
# /subject   => Subject as rfc2253 string
# /subject/N => Subject alt names with N counting from 1. The format is either an rfc2253 string as
#               used above, an rfc2822 mailbox name indicated by the first character being a left
#               angle bracket or an S-expression in advanced format for all other types of
#               subjectAltnames which is indicated by an opening parentheses.
# /notBefore => The activation time in UTC in ISO time format.
# /notAfter  => The expiration time in UTC in ISO time format.
# /fprSHA1   => The SHA-1 fingerprint
# /fprSHA256 => The SHA-256 fingerprint
# /image     => The entire certificate as a base64 encoded string.
# /hostnames => All hostnames (CN from subject and all dns-name altSubjectNames) as a comma
#               delimited string.
# /signature-algorithm => The algorithm name used to sign the certificate. See the following list
#               for a possible return values:
#               https://github.com/greenbone/openvas-scanner/blob/3409c714417a395239018b05e4af67b5d60d4ed1/nasl/nasl_cert.c#L564-L660
# /public-key-size => The size (in bits) of the public key
# /public-key-algorithm => The algorithm name of the public key. Only available / set on GOS
#               21.04.11 / openvas-scanner 21.4.4 or later. See the following URL for an overview
#               on the returned values:
#               https://github.com/gnutls/gnutls/blob/19945cb637c9def9f79fa2edcab4bc63a5084791/lib/algorithms/publickey.c#L119-L153
#               Examples: "EC/ECDSA" or "RSA"
#
# These entries give detailed information about a certificate. A server may return several
# certificates: The actual server certificates may be followed by other certificates which make up
# the chain. Further the server may return different certificates depending on the SNI. To collect
# these details we use these entries:
#
# HostDetails/SSLInfo/<port>        <fingerprint>, <fingerprint>, ...
# HostDetails/SSLInfo/<port>/<host> <fingerprint>, <fingerprint>, ...
#
# If there is an error with one of the certificates, the fingerprint is replaced by the string
# "[ERROR]". VTs evaluating the fingerprints should thus check whether first character of each
# fingerprint is a '['.
#
# The preliminary report format is:
#
# <host>
#   <detail>
#     <name>Cert:SHA256_HEXSTRING</name>
#     <value>x509:BASE64_STRING</value>
#   </detail>
#   <detail>
#     <name>SSLDetails:SHA256_HEXSTRING</name>
#     <value>serial:HEX_STRING|hostnames:HOSTS|notBefore:UTC_ISO|notAfter:UTC_ISO</value>
#   </detail>
#   <detail>
#     <name>SSLInfo</name>
#     <value>PORT:HOSTNAME:FINGERPRINT_LIST</value>
#   </detail>
# </host>
##

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103692");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2013-04-09 14:14:14 +0200 (Tue, 09 Apr 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: Collect and Report Certificate Details");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl", "gb_ssl_tls_sni_supported.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This script collects and reports the details of all SSL/TLS
  certificates.

  This data will be used by other tests to verify server certificates.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("mysql.inc");
include("xml.inc");
include("host_details.inc");
include("list_array_func.inc");

function read_and_parse_certs( cert, port ) {

  local_var cert, port;
  local_var certobj, serial, issuer, subject, not_before, not_after, fpr_sha_1, fpr_sha_256, image, hostnames, algorithm_name, key_size, public_key_algo;
  local_var idx, tmp, prefix, public_key_algo, item;

  if( ! cert ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cert#-#read_and_parse_certs" );
    return;
  }

  if( ! certobj = cert_open( cert ) ) {
    set_kb_item( name:"HostDetails/SSLInfo/" + port, value:"[ERROR]" );
    log_message( data:"The certificate of the remote service cannot be parsed by the scanner function cert_query()!", port:port );
    return;
  }

  # nb: The "failed to extract" text is used below in a few checks. Make sure to update these if the
  # string is ever getting changed.
  if( ! serial = cert_query( certobj, "serial" ) ) {
    serial = "Scanner (cert_query()) failed to extract 'serial' from certificate";
  }

  if( ! issuer = cert_query( certobj, "issuer" ) ) {
    issuer = "Scanner (cert_query()) failed to extract 'issuer' from certificate";
  }

  if( ! subject = cert_query( certobj, "subject" ) ) {
    subject = "Scanner (cert_query()) failed to extract 'subject' from certificate";
  }

  if( ! not_before = cert_query( certobj, "not-before" ) ) {
    not_before = "Scanner (cert_query()) failed to extract 'not-before' from certificate";
  }

  if( ! not_after = cert_query( certobj, "not-after" ) ) {
    not_after = "Scanner (cert_query()) failed to extract 'not-after' from certificate";
  }

  if( ! fpr_sha_1 = cert_query( certobj, "fpr-sha-1" ) ) {
    fpr_sha_1 = "Scanner (cert_query()) failed to extract 'fpr-sha-1' from certificate";
  }

  if( ! fpr_sha_256 = cert_query( certobj, "fpr-sha-256" ) ) {
    fpr_sha_256 = "Scanner (cert_query()) failed to extract 'fpr-sha-256' from certificate";
  }

  if( ! image = cert_query( certobj, "image" ) ) {
    image = "Scanner (cert_query()) failed to extract 'image' from certificate";
  } else {
    image = base64( str:image );
  }

  if( ! hostnames = cert_query( certobj, "hostnames" ) ) {
    hostnames = "Scanner (cert_query()) failed to extract 'hostnames' from certificate";
  } else {
    # nb: Some certs might have something like e.g.:
    # subject: CN=foo.example.com
    # dns-name: foo.example.com
    # dns-name: bar.example.com
    # In this case we're getting all three hostnames here like:
    # [ 0: 'foo.example.com', 1: 'foo.example.com', 2: 'bar.example.com' ]
    # Before passing this list to the code below we're making it "unique" to avoid having doubled
    # hostnames in the list.
    hostnames = make_list_unique( hostnames );
  }

  # TODO: Change to "signature-algorithm-name" once GOS / GVM 21.04.x is EOL.
  if( ! algorithm_name = cert_query( certobj, "algorithm-name" ) ) {
    algorithm_name = "Scanner (cert_query()) failed to extract 'algorithm-name' from certificate";
  }

  if( ! key_size = cert_query( certobj, "key-size" ) ) {
    key_size = "Scanner (cert_query()) failed to extract 'key-size' from certificate";
  }

  # nb: Available since GOS 21.04.11 / openvas-scanner 21.4.4
  if( ! public_key_algo = cert_query( certobj, "public-key-algorithm-name" ) ) {
    public_key_algo = "Scanner (cert_query()) failed to extract 'public-key-algorithm-name' from certificate";
  }

  if( log_verbosity > 1 ) {
    debug_print( "SSL/TLS certificate on port ", port, ":\n" );
    debug_print( "serial .................: ", serial, "\n" );
    debug_print( "issuer .................: ", issuer, "\n" );
    debug_print( "subject ................: ", subject, "\n" );
    for( idx = 1; ( tmp = cert_query( certobj, "subject", idx:idx ) ); idx++ ) {
      if( tmp )
        debug_print( "altSubjectName[", idx, "]: ", tmp, "\n" );
      else
        debug_print( "altSubjectName[", idx, "]: Scanner (cert_query()) failed to extract altSubjectName from certificate\n" );
    }
    debug_print( "notBefore ..............: ", not_before, "\n" );
    debug_print( "notAfter ...............: ", not_after, "\n" );
    debug_print( "fpr (SHA-1) ............: ", fpr_sha_1, "\n" );
    debug_print( "fpr (SHA-256) ..........: ", fpr_sha_256, "\n" );
    debug_print( "image ..................: ", image, "\n" );
    debug_print( "hostnames ..............: ", hostnames, "\n" );
    debug_print( "signature algorithm ....: ", algorithm_name, "\n" );
    debug_print( "public key size (bits) .: ", key_size, "\n" );
    debug_print( "public key algorithm ...: ", public_key_algo, "\n" );
  }

  if( ! fpr_sha_256 || " failed to extract " >< fpr_sha_256 ) {
    cert_close( certobj );
    set_kb_item( name:"HostDetails/SSLInfo/" + port, value:"[ERROR]" );
    log_message( data:"The certificates SHA-256 fingerprint of the remote service cannot be gathered by the scanner function cert_query()!", port:port );
    return;
  }

  # Insert the certificiate details into the list of certificates if not already done. Because we
  # use the fingerprint we know that all KB items of the certificate will be identical (unless a
  # script was changed during a run).
  prefix = "HostDetails/Cert/" + fpr_sha_256;
  if( isnull( get_kb_item( prefix + "/type" ) ) ) {

    set_kb_item( name:prefix + "/type", value:"X.509" );

    # nb: We only want to add the KB key info if the cert_query() call hasn't failed.
    if( serial && " failed to extract " >!< serial )
      set_kb_item( name:prefix + "/serial", value:serial );

    if( issuer && " failed to extract " >!< issuer )
      set_kb_item( name:prefix + "/issuer", value:issuer );

    if( subject && " failed to extract " >!< subject )
      set_kb_item( name:prefix + "/subject", value:subject );

    for( idx = 1; ( tmp = cert_query( certobj, "subject", idx:idx ) ); idx++ ) {
      if( tmp )
        set_kb_item( name:prefix + "/subject/" + idx, value:tmp );
    }

    if( not_before && " failed to extract " >!< not_before )
      set_kb_item( name:prefix + "/notBefore", value:not_before );

    if( not_after && " failed to extract " >!< not_after )
      set_kb_item( name:prefix + "/notAfter", value:not_after );

    if( fpr_sha_1 && " failed to extract " >!< fpr_sha_1 )
      set_kb_item( name:prefix + "/fprSHA1", value:fpr_sha_1 );

    if( fpr_sha_256 && " failed to extract " >!< fpr_sha_256 )
      set_kb_item( name:prefix + "/fprSHA256", value:fpr_sha_256 );

    if( image && " failed to extract " >!< image )
      set_kb_item( name:prefix + "/image", value:image );

    if( algorithm_name && " failed to extract " >!< algorithm_name )
      set_kb_item( name:prefix + "/signature-algorithm", value:algorithm_name );

    if( key_size && " failed to extract " >!< key_size )
      set_kb_item( name:prefix + "/public-key-size", value:key_size );

    if( public_key_algo && " failed to extract " >!< public_key_algo )
      set_kb_item( name:prefix + "/public-key-algorithm", value:public_key_algo );

    if( hostnames && " failed to extract " >!< hostnames ) {
      tmp = "";
      foreach item( hostnames ) {
        if( tmp != "" )
          tmp += ",";
        tmp += item;
      }
      set_kb_item( name:prefix + "/hostnames", value:tmp );
    }
  }

  cert_close( certobj );

  # FIXME: Extend get_server_cert and return an array of certificates.
  # FIXME: What to do if the server returns random certificates?
  # FIXME: We need a list of virtual hostnames to request certificates using the SNI.

  set_kb_item( name:"HostDetails/SSLInfo/" + port, value:fpr_sha_256 );
  set_kb_item( name:"ssl/cert/avail", value:TRUE ); # dummy for broken script_mandatory_keys when KB entry is a list

  return;
}

function report_ssl_cert_details() {

  local_var oid, certs, key, tmp, fpr, issuer, serial, not_before, not_after, image;
  local_var ssls, collected_certs, port, host, report;

  oid = "1.3.6.1.4.1.25623.1.0.103692";

  certs = get_kb_list( "HostDetails/Cert/*/type" );
  if( certs ) {
    foreach key( keys( certs ) ) {

      tmp = split( key, sep:"/", keep:FALSE );
      fpr = tmp[2];
      issuer = get_kb_item( "HostDetails/Cert/" + fpr + "/issuer" );
      serial = get_kb_item( "HostDetails/Cert/" + fpr + "/serial" );
      not_before = get_kb_item( "HostDetails/Cert/" + fpr + "/notBefore" );
      not_after = get_kb_item( "HostDetails/Cert/" + fpr + "/notAfter" );
      image = get_kb_item( "HostDetails/Cert/" + fpr + "/image" );

      tmp = "issuer:" + issuer + "|serial:" + serial + "|notBefore:" + not_before + "|notAfter:" + not_after;

      report_host_detail_single( name:"Cert:" + fpr, value:"x509:" + image, nvt:oid, desc:"SSL/TLS Certificate" );
      report_host_detail_single( name:"SSLDetails:" + fpr, value:tmp, nvt:oid, desc:"SSL/TLS Certificate Details" );
    }
  }

  ssls = get_kb_list( "HostDetails/SSLInfo/*" );
  if( ssls ) {

    collected_certs = make_list();

    foreach key( keys( ssls ) ) {
      tmp = split( key, sep:"/", keep:FALSE );
      port = tmp[2];
      host = tmp[3];
      tmp = port + ":" + host + ":" + get_kb_item( key );

      report_host_detail_single( name:"SSLInfo", value:tmp, nvt:oid, desc:"SSL/TLS Certificate Information" );

      key = "HostDetails/Cert/" + fpr + "/";
      collected_certs[port] = key;
    }

    foreach port( keys( collected_certs ) ) {

      # nb:
      # - Store the reference from this one to some VTs like e.g.
      #   gb_ssl_tls_cert_common_name_fqdn.nasl using the info collected here to show a
      #   cross-reference within the reports
      # - We're not using register_product() here as we don't want to register the protocol within
      #   this VT (as the CPEs are already registered in gb_ssl_tls_version_get.nasl) by but just want
      #   to make use of the functionality to show the reference in the reports
      # - Also using only the TLS relevant CPE here on purpose (and not the SSL one) just to have
      #   one more generic assigned
      # - If changing the syntax of e.g. the port + "/tcp" below make sure to update VTs like e.g. the
      #   gb_ssl_tls_cert_common_name_fqdn.nasl accordingly
      register_host_detail( name:"SSL/TLS: Collect and Report Certificate Details", value:"cpe:/a:ietf:transport_layer_security" );
      register_host_detail( name:"cpe:/a:ietf:transport_layer_security", value:port + "/tcp" );
      register_host_detail( name:"port", value:port + "/tcp" );

      report = 'The following certificate details of the remote service were collected.\n';
      report += cert_summary( key:collected_certs[port] );
      log_message( data:report, port:port );
    }
  }
}

portlist = get_kb_list( "ssl_tls/port" );
foreach port( portlist ) {
  cert = get_server_cert( port:port );
  if( cert ) {
    read_and_parse_certs( cert:cert, port:port );
  }
}

report_ssl_cert_details();

exit( 0 );
