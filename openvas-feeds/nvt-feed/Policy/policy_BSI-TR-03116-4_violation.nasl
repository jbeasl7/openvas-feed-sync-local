# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96179");
  script_version("2020-03-31T06:57:15+0000");
  script_tag(name:"last_modification", value:"2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-03-07 09:23:42 +0100 (Mon, 07 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("BSI-TR-03116-4: Violations");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/policy_BSI-TR-03116-4.nasl");
  script_mandatory_keys("policy/BSI-TR-03116-4/fail", "ssl_tls/port");

  script_tag(name:"summary", value:"List negative results from Policy for BSI-TR-03116-4 Test.");

  script_tag(name:"insight", value:"Mindestens zu unterstuetzenden Cipher Suites:

  - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

  - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

  Sofern anwendungsbezogen Cipher Suites eingesetzt werden, bei denen zusaetzlich
  zur Authentisierung des Servers via Zertifikaten vorab ausgetauschte Daten
  (Pre-Shared-Key, PSK) in die Authentisierung und Schluesseleinigung einfliessen,
  muss mindestens die folgende Cipher Suite unterstuetzt werden:

  - TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");

  script_tag(name:"solution", value:"Remove superfluous or add minimal required Cipher Suites.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

result = get_kb_item( "policy/BSI-TR-03116-4/" + port + "/fail" );

if( result )
  security_message( port:port, data:result );

exit( 0 );
