# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802087");
  script_version("2024-09-30T08:38:05+0000");
  script_cve_id("CVE-2014-3566");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-30 08:38:05 +0000 (Mon, 30 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"creation_date", value:"2014-10-16 17:29:43 +0530 (Thu, 16 Oct 2014)");
  script_name("SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerability (POODLE)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl", "gb_tls_fallback_scsv_enabled.nasl");
  script_mandatory_keys("ssl_tls/ciphers/supported_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70574");
  script_xref(name:"URL", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_xref(name:"URL", value:"https://www.dfranke.us/posts/2014-10-14-how-poodle-happened.html");
  script_xref(name:"URL", value:"http://googleonlinesecurity.blogspot.in/2014/10/this-poodle-bites-exploiting-ssl-30.html");

  script_tag(name:"summary", value:"This host is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Evaluate previous collected information about this service.");

  script_tag(name:"insight", value:"The flaw is due to the block cipher padding not being deterministic and not covered by the Message Authentication Code");

  script_tag(name:"impact", value:"Successful exploitation will allow a  man-in-the-middle attackers gain access to the plain text data stream.");

  script_tag(name:"solution", value:"Possible Mitigations are:

  - Disable SSLv3

  - Disable cipher suites supporting CBC cipher modes

  - Enable TLS_FALLBACK_SCSV if the service is providing TLSv1.0+");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! tls_versions = get_kb_item( "tls/supported/" + port ) )
  exit( 0 );

if( "SSLv3" >!< tls_versions )
  exit( 0 );

# If SSLv3 is supported then check if CBC ciphers are supported and exit if not
if( ! cipherList = get_kb_list( "ssl_tls/ciphers/sslv3/" + port + "/supported_ciphers" ) )
  exit( 0 );

if( ! in_array( search:"_CBC_", array:cipherList, part_match:TRUE ) )
  exit( 0 );

# If TLSv1.0+ is available check if TLS_FALLBACK_SCSV is supported and mark as vulnerable if not
if( "TLSv" >< tls_versions ) {
  if( ! get_kb_item( "tls_fallback_scsv_supported/" + port ) ) {
    VULN = TRUE;
  }
} else {
  VULN = TRUE;
}

if( VULN ) {

  # nb:
  # - Store the reference from this one to gb_ssl_tls_ciphers_report.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.802067" ); # gb_ssl_tls_ciphers_report.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  security_message( port:port );
  exit( 0 );
}

exit( 99 );
