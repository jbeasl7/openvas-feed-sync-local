# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140038");
  script_version("2021-09-24T07:45:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-24 07:45:50 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-11-01 09:34:04 +0100 (Tue, 01 Nov 2016)");
  script_name("SSL/TLS: Cert Issuer Policy Check");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_tls_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port", "ssl_tls/cert_chain/extracted");

  script_add_preference(name:"Perform check:", type:"checkbox", value:"no", id:1);
  script_add_preference(name:"Certificate Issuer", value:"", type:"entry", id:2);
  script_add_preference(name:"Report passed tests:", type:"checkbox", value:"no", id:3);

  script_tag(name:"summary", value:"Checks if the SSL/TLS certificate is signed by the given issuer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("ssl_funcs.inc");
include("misc_func.inc");

pf = script_get_preference("Perform check:", id:1);
if( pf != "yes" )
  exit( 0 );

set_kb_item( name:"policy_cert_issuer/run_test", value:TRUE );

check_issuer = script_get_preference("Certificate Issuer", id:2);
if( ! check_issuer )
  exit( 0 );

check_issuer = ereg_replace( pattern:'^\\s*', replace:"", string:check_issuer );
check_issuer = ereg_replace( pattern:'\\s*$', replace:"", string:check_issuer );
check_issuer = ereg_replace( pattern:'\r', replace:"", string:check_issuer );
check_issuer = ereg_replace( pattern:'\n', replace:"", string:check_issuer );

check_issuer = chomp( check_issuer );
if( ! check_issuer )
  exit( 0 );

if( ! port = tls_ssl_get_port() )
  exit( 0 );

rpt = script_get_preference("Report passed tests:", id:3);
if( rpt == 'yes' )
  set_kb_item( name:"policy_cert_issuer/report_passed_tests", value:TRUE );

set_kb_item( name:"policy_cert_issuer/check_issuer", value:check_issuer );

server_cert = get_kb_item( "ssl_tls/cert_chain/" + port + "/certs/server_cert" );
if( ! server_cert )
  exit( 0 );

server_cert = base64_decode( str:server_cert );

if( ! certobj = cert_open( server_cert ) )
  exit( 0 );

issuer = cert_query( certobj, "issuer" );
cert_close( certobj );
if( ! issuer )
  exit( 0 );

set_kb_item( name:"policy_cert_issuer/" + port + "/issuer", value:issuer );

if( check_issuer != issuer )
  set_kb_item( name:"policy_cert_issuer/" + port + "/failed", value:TRUE );
else
  set_kb_item( name:"policy_cert_issuer/" + port + "/passed", value:TRUE );

exit( 0 );