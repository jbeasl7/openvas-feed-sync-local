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

# How many days in advance to warn of certificate expiry.
lookahead = 60;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105891");
  script_version("2022-05-23T11:42:08+0000");
  script_tag(name:"last_modification", value:"2022-05-23 11:42:08 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2016-09-16 11:11:32 +0200 (Fri, 16 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("SSL/TLS: Certificate In Chain Will Soon Expire");

  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_tls_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port", "ssl_tls/cert_chain/extracted");

  script_tag(name:"insight", value:"Checks expiry dates of certificates in the chain associated
  with SSL/TLS-enabled services on the target and reports whether any will expire during then next " +
  lookahead + " days.");

  script_tag(name:"solution", value:"Prepare to replace the SSL/TLS certificate by a new one.");

  script_tag(name:"summary", value:"A certificate in the chain of the remote server will soon expire.");

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

function check_validity( port, now, future ) {

  local_var port, now, future;
  local_var c, expired, f, certobj, expire_date, subject;

  if( ! port )
    return;

  if( ! c = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/chain" ) )
    exit( 0 );

  expired = make_list();

  foreach f( c ) {

    f = base64_decode( str:f );

    if( ! certobj = cert_open( f ) )
      continue;

    expire_date = cert_query( certobj, "not-after" );

    # Don't report if already expired (handled in 2016/gb_ssl_tls_cert_chain_expired.nasl)
    if( expire_date < now ) {
      cert_close( certobj );
      continue;
    }

    if( expire_date < future ) {
      subject = cert_query( certobj, "subject" );
      expired = make_list( expired, subject + ">##<" + expire_date );
    }

    cert_close( certobj );
  }

  if( max_index( expired ) > 0 )
    return expired;

  return;
}

if( ! port = tls_ssl_get_port() )
  exit( 0 );

now = isotime_now();
if( strlen( now ) <= 0 )
  exit( 0 ); # isotime_now: "If the current time is not available an empty string is returned."

future = isotime_add( now, days:lookahead );
if( isnull( future ) )
  exit( 0 ); # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).

if( ret = check_validity( port:port, now:now, future:future ) ) {
  foreach a( ret ) {
    exp = split( a, sep:">##<", keep:FALSE );

    subj = exp[0];
    exp_date = exp[1];

    report_expired += 'Subject:     ' + subj + '\nExpired on:  ' + isotime_print( exp_date ) + '\n\n';
  }

  report = 'The following certificate(s) in the chain of the remote service will expire soon.\n\n' +
           report_expired;
  log_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
