# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103440");
  script_version("2025-03-27T05:38:50+0000");
  script_cve_id("CVE-2013-2566", "CVE-2015-2808", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 19:48:00 +0000 (Mon, 23 Nov 2020)");
  script_tag(name:"creation_date", value:"2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)");
  script_name("SSL/TLS: Report Weak Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("ssl_tls/ciphers/weak_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://ssl-config.mozilla.org");
  # nb: Some of the BSI documents are only available in German and thus no english variants have
  # been used here.
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Mindeststandards/TLS-Protokoll/TLS-Protokoll_node.html");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.html");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Mindeststandards/Mindeststandard_BSI_TLS_Version_2_4.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20240113175943/https://www.bettercrypto.org");
  script_xref(name:"URL", value:"https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014");

  script_tag(name:"summary", value:"This routine reports all weak SSL/TLS cipher suites accepted by
  a service.");

  script_tag(name:"vuldetect", value:"Checks previous collected cipher suites.

  NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp
  is reported. If too strong cipher suites are configured for this service the alternative would be
  to fall back to an even more insecure cleartext communication.");

  script_tag(name:"insight", value:"These rules are applied for the evaluation of the cryptographic
  strength:

  - RC4 is considered to be weak (CVE-2013-2566, CVE-2015-2808)

  - Ciphers using 64 bit or less are considered to be vulnerable to brute force methods and
  therefore considered as weak (CVE-2015-4000)

  - 1024 bit RSA authentication is considered to be insecure and therefore as weak

  - Any cipher considered to be secure for only the next 10 years is considered as medium

  - Any other cipher is considered as strong");

  script_tag(name:"impact", value:"This could allow remote attackers to obtain sensitive information
  or have other, unspecified impacts.");

  script_tag(name:"affected", value:"All services providing an encrypted communication using weak
  SSL/TLS cipher suites.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so that it
  does not accept the listed weak cipher suites anymore.

  Please see the references for more resources supporting you with this task.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("gb_print_ciphers.inc");
include("port_service_func.inc");
include("host_details.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"weak" );

if( report ) {

  # nb:
  # - Store the reference from this one to gb_ssl_tls_ciphers_report.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.802067" ); # gb_ssl_tls_ciphers_report.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  if( port == "25" ) {
    if( ports = smtp_get_ports( default_port_list:make_list( 25 ) ) ) {
      if( in_array( search:"25", array:ports ) ) {
        tmpreport = "NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp is reported. ";
        tmpreport += "If too strong cipher suites are configured for this service the alternative would be to fall back to an even more insecure cleartext communication.";
        log_message( port:port, data:tmpreport + '\n\n' + report );
        exit( 0 );
      }
    }
  }

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
