# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900234");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2010-04-13 17:43:57 +0200 (Tue, 13 Apr 2010)");
  script_name("SSL/TLS: Check Supported Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_ssl_tls_ciphers_setting.nasl", "gb_ssl_tls_sni_supported.nasl",
                      "gb_ssl_tls_version_get.nasl");
  script_family("SSL and TLS");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This routine connects to a SSL/TLS service and checks the
  quality of the accepted cipher suites.");

  script_tag(name:"insight", value:"Notes:

  - Depending on the amount of services offered by this host, the routine might take good amount of
  time to complete, it is advised to increase the timeout.

  - As this VT might run into a timeout the actual reporting of all accepted cipher suites takes
  place in the VT 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067)
  instead.

  - SSLv2 ciphers are not getting enumerated as the protocol itself is deprecated, needs to be
  considered as weak and is reported separately as deprecated.");

  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(3600);

  exit(0);
}

include("mysql.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("gb_ssl_tls_ciphers.inc");
include("byte_func.inc");
include("list_array_func.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! tls_versions = get_kb_list( "tls_version_get/" + port  + "/version") )
  exit( 0 );

tls_type = get_kb_item( "starttls_typ/" + port );

set_kb_item( name:"ssl_tls/ciphers/gathering/started", value:TRUE );

if( tls_type && tls_type == "mysql" )
  check_single_cipher( tls_versions:tls_versions, port:port );
else
  check_all_cipher( tls_versions:tls_versions, port:port );

exit( 0 );
