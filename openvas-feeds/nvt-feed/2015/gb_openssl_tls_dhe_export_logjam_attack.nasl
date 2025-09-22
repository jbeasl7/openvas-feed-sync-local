# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805188");
  script_version("2025-03-27T05:38:50+0000");
  script_cve_id("CVE-2015-4000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2015-05-22 13:17:23 +0530 (Fri, 22 May 2015)");
  script_name("SSL/TLS: 'DHE_EXPORT' MITM Security Bypass Vulnerability (LogJam)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("ssl_tls/ciphers/supported_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://weakdh.org");
  script_xref(name:"URL", value:"https://weakdh.org/sysadmin.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122160144/http://www.securityfocus.com/bid/74733");
  script_xref(name:"URL", value:"https://weakdh.org/imperfect-forward-secrecy.pdf");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2015/05/20/8");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained");
  script_xref(name:"URL", value:"https://openssl-library.org/post/2015-05-20-logjam-freak-upcoming-changes/index.html");
  script_xref(name:"URL", value:"https://ssl-config.mozilla.org");
  # nb: Some of the BSI documents are only available in German and thus no english variants have
  # been used here.
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Mindeststandards/TLS-Protokoll/TLS-Protokoll_node.html");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.html");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Mindeststandards/Mindeststandard_BSI_TLS_Version_2_4.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20240113175943/https://www.bettercrypto.org");
  script_xref(name:"URL", value:"https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014");

  script_tag(name:"summary", value:"This host is accepting 'DHE_EXPORT' cipher suites and is prone
  to a man-in-the-middle (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks previous collected cipher suites.");

  script_tag(name:"insight", value:"Flaw is triggered when handling Diffie-Hellman key exchanges
  defined in the 'DHE_EXPORT' cipher suites.");

  script_tag(name:"impact", value:"Successful exploitation will allow a man-in-the-middle attacker
  to downgrade the security of a TLS session to 512-bit export-grade cryptography, which is
  significantly weaker, allowing the attacker to more easily break the encryption and monitor or
  tamper with the encrypted stream.");

  script_tag(name:"affected", value:"- Hosts accepting 'DHE_EXPORT' cipher suites.

  - OpenSSL versions prior to 1.0.1n and 1.0.2 prior to 1.0.2b.");

  script_tag(name:"solution", value:"- Remove support for 'DHE_EXPORT' cipher
  suites from the service. Please see the references for more resources supporting you with this
  task.

  - If the service is using OpenSSL: Update to version 1.0.1n, 1.0.2b or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssl_funcs.inc");
include("host_details.inc");

cipherText = "'DHE_EXPORT' cipher suites";

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! sup_ssl = get_kb_item( "tls/supported/" + port ) )
  exit( 0 );

if( "SSLv3" >< sup_ssl ) {
  sslv3CipherList = get_kb_list( "ssl_tls/ciphers/sslv3/" + port + "/supported_ciphers" );

  if( ! isnull( sslv3CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    sslv3CipherList = sort( sslv3CipherList );

    foreach sslv3Cipher( sslv3CipherList ) {
      if( sslv3Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        sslv3Vuln = TRUE;
        sslv3tmpReport += sslv3Cipher + '\n';
      }
    }

    if( sslv3Vuln ) {
      report += cipherText +' accepted by this service via the SSLv3 protocol:\n\n' + sslv3tmpReport + '\n';
    }
  }
}

if( "TLSv1.0" >< sup_ssl ) {
  tlsv1_0CipherList = get_kb_list( "ssl_tls/ciphers/tlsv1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_0CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_0CipherList = sort( tlsv1_0CipherList );

    foreach tlsv1_0Cipher( tlsv1_0CipherList ) {
      if( tlsv1_0Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        tlsv1_0Vuln = TRUE;
        tlsv1_0tmpReport += tlsv1_0Cipher + '\n';
      }
    }

    if( tlsv1_0Vuln ) {
      report += cipherText + ' accepted by this service via the TLSv1.0 protocol:\n\n' + tlsv1_0tmpReport + '\n';
    }
  }
}

if( "TLSv1.1" >< sup_ssl ) {
  tlsv1_1CipherList = get_kb_list( "ssl_tls/ciphers/tlsv1_1/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_1CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_1CipherList = sort( tlsv1_1CipherList );

    foreach tlsv1_1Cipher( tlsv1_1CipherList ) {
      if( tlsv1_1Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        tlsv1_1Vuln = TRUE;
        tlsv1_1tmpReport += tlsv1_1Cipher + '\n';
      }
    }

    if( tlsv1_1Vuln ) {
      report += cipherText + ' accepted by this service via the TLSv1.1 protocol:\n\n' + tlsv1_1tmpReport + '\n';
    }
  }
}

if( "TLSv1.2" >< sup_ssl ) {
  tlsv1_2CipherList = get_kb_list( "ssl_tls/ciphers/tlsv1_2/" + port + "/supported_ciphers" );

  if( ! isnull( tlsv1_2CipherList ) ) {

    # Sort to not report changes on delta reports if just the order is different
    tlsv1_2CipherList = sort( tlsv1_2CipherList );

    foreach tlsv1_2Cipher( tlsv1_2CipherList ) {
      if( tlsv1_2Cipher =~ "^TLS_DHE?_.*_EXPORT_" ) {
        tlsv1_2Vuln = TRUE;
        tlsv1_2tmpReport += tlsv1_2Cipher + '\n';
      }
    }

    if( tlsv1_2Vuln ) {
      report += cipherText + ' accepted by this service via the TLSv1.2 protocol:\n\n' + tlsv1_2tmpReport + '\n';
    }
  }
}

if( report ) {

  # nb:
  # - Store the reference from this one to gb_ssl_tls_ciphers_report.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.802067" ); # gb_ssl_tls_ciphers_report.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
