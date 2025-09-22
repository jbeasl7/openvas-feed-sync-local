# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802056");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2002-2443");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-06-20 10:48:39 +0530 (Thu, 20 Jun 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("MIT Kerberos 5 kpasswd UDP Packet DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60008");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q2/316");
  script_xref(name:"URL", value:"http://krbdev.mit.edu/rt/Ticket/Display.html?id=7637");
  script_xref(name:"URL", value:"https://github.com/krb5/krb5/commit/cf1a0c411b2668c57c41e9c4efd15ba17b6b322c");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kerberos_detect.nasl", "gb_kerberos_detect_udp.nasl");
  script_require_udp_ports(464);
  # nb: Don't use kerberos/udp/detected here because the detection of Kerberos might worked for TCP
  # via 88/tcp only but the port 464/udp of kpasswd still might be exposed / vulnerable.
  script_mandatory_keys("kerberos/detected");

  script_tag(name:"summary", value:"MIT Kerberos is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The flaw exists because the kpasswd application does not
  properly validate UDP packets before sending responses and can be exploited to exhaust CPU and
  network resources via the UDP 'ping-pong' attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a DoS via a
  forged packet that triggers a communication loop.");

  script_tag(name:"affected", value:"MIT Kerberos 5 before 1.11.3.");

  script_tag(name:"solution", value:"Update to MIT Kerberos 5 version 1.11.3 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("network_func.inc");

# nb: kpasswd UDP port
port = 464;
if(!check_udp_port_status(dport:port))
  exit(0);

if(!sock = open_sock_udp(port))
  exit(0);

## Some crap data
crap_data = crap(25);

send(socket:sock, data:crap_data);
res = recv(socket:sock, length:512);
close(sock);

## If kpasswd responds means it's vulnerable to ping-pong attack
if("kadmin" >< res && "changepw" >< res) {
  security_message(port:port, protocol:"udp");
  exit(0);
}

exit(99);