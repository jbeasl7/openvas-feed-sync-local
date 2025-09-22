# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802067");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2014-03-06 17:20:28 +0530 (Thu, 06 Mar 2014)");
  script_name("SSL/TLS: Report Supported Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("ssl_tls/ciphers/supported_ciphers", "ssl_tls/ciphers/gathering/started",
                        "ssl_tls/port");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs to
  # choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd database.

  script_tag(name:"summary", value:"This routine reports all SSL/TLS cipher suites accepted by a
  service.");

  script_tag(name:"insight", value:"Notes:

  - As the VT 'SSL/TLS: Check Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.900234) might run
  into a timeout the actual reporting of all accepted cipher suites takes place in this VT instead.

  - SSLv2 ciphers are not getting reported as the protocol itself is deprecated, needs to be
  considered as weak and is reported separately as deprecated.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("gb_print_ciphers.inc");
include("host_details.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"strong,medium,weak,null,anon", negative:TRUE );

if( report ) {

  # nb:
  # - Store the reference from this one to some VTs like e.g.
  #   gb_ssl_tls_CVE-2002-20001_CVE-2022-40735.nasl using the info collected here to show a
  #   cross-reference within the reports
  # - We're not using register_product() here as we don't want to register the protocol within this
  #   VT (as the CPEs are already registered in gb_ssl_tls_version_get.nasl) by but just want to make
  #   use of the functionality to show the reference in the reports
  # - Also using only the TLS relevant CPE here on purpose (and not the SSL one) just to have one
  #   more generic assigned
  # - If changing the syntax of e.g. the port + "/tcp" below make sure to update VTs like e.g. the
  #   gb_ssl_tls_CVE-2002-20001_CVE-2022-40735.nasl accordingly
  register_host_detail( name:"SSL/TLS: Report Supported Cipher Suites", value:"cpe:/a:ietf:transport_layer_security" );
  register_host_detail( name:"cpe:/a:ietf:transport_layer_security", value:port + "/tcp" );
  register_host_detail( name:"port", value:port + "/tcp" );

  log_message( port:port, data:report );
}

exit( 0 );
