# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150710");
  script_version("2021-12-10T12:48:00+0000");
  script_tag(name:"last_modification", value:"2021-12-10 12:48:00 +0000 (Fri, 10 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-09-07 10:07:44 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-11-23 10:58:59 +0000 (Tue, 23 Nov 2021)");

  script_name("SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port", "ssl_tls/cert_chain/extracted");

  script_tag(name:"summary", value:"The remote SSL/TLS server certificate and/or any of the
  certificates in the certificate chain is using a RSA key with less than 2048 bits.");

  script_tag(name:"vuldetect", value:"Checks the RSA keys size of the server certificate and all
  certificates in chain for a size < 2048 bit.");

  script_tag(name:"insight", value:"SSL/TLS certificates using RSA keys with less than 2048 bits are
  considered unsafe.");

  script_tag(name:"impact", value:"Using certificates with weak RSA key size can lead to
  unauthorized exposure of sensitive information.");

  script_tag(name:"solution", value:"Replace the certificate with a stronger key and reissue the
  certificates it signed.");

  script_xref(name:"URL", value:"https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

# nb: Check the server certificate first
if( ! server_cert = get_kb_item( "ssl_tls/cert_chain/" + port + "/certs/server_cert" ) )
  exit( 0 );

# The list of supported algorithms can be seen here:
# https://github.com/gnutls/gnutls/blob/19945cb637c9def9f79fa2edcab4bc63a5084791/lib/algorithms/publickey.c#L119-L153
check_algorithms = "^(RSA|RSA-PSS|RSA \(X\.509\)|RSA-MD5|RSA-SHA1|RSA-SHA1)$";

min_key_size = 2048;

if( unsafe_cert = tls_ssl_check_small_cert_key_size( cert:server_cert, algorithm_name:check_algorithms, min_key_size:min_key_size ) )
  report = '\n' + unsafe_cert["public-key-size"] + ":" + unsafe_cert["public-key-algorithm"] + ":" + unsafe_cert["serial"] + ":" + unsafe_cert["issuer"] + " (Server certificate)";

chain = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/chain" );
foreach cert( chain ) {
  if( unsafe_cert = tls_ssl_check_small_cert_key_size( cert:cert, algorithm_name:check_algorithms, min_key_size:min_key_size ) )
    report += '\n' + unsafe_cert["public-key-size"] + ":" + unsafe_cert["public-key-algorithm"] + ":" + unsafe_cert["serial"] + ":" + unsafe_cert["issuer"] + " (Certificate in chain)";
}

if( report ) {
  security_message( port:port, data:'The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than ' + min_key_size + ' bits (public-key-size:public-key-algorithm:serial:issuer):\n' + report );
  exit( 0 );
}

exit( 99 );