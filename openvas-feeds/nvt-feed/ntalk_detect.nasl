# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10168");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Detect talkd server port and protocol version");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_require_udp_ports(518);

  script_tag(name:"solution", value:"Disable talkd access from the network by adding the appropriate rule on your
  firewall. If you do not need talkd, comment out the relevant line in
  /etc/inetd.conf and restart the inetd process.");
  script_tag(name:"summary", value:"The remote host is running a 'talkd' daemon.

  talkd is the server that notifies a user that someone else wants to initiate
  a conversation with him.");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-1997-04.html");
  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

dstport = 518;
if(!get_udp_port_state(dstport))
  exit(0);

soc = open_sock_udp(dstport);
if(!soc)
  exit(0);

srcaddr = this_host();
a1 = ereg_replace(pattern:"([0-9]*)\.[0-9]*\.[0-9]*\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a1 = a1 % 255;

a2 = ereg_replace(pattern:"[0-9]*\.([0-9]*)\.[0-9]*\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a2 = a2 % 255;

a3 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.([0-9]*)\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a3 = a3 % 255;

a4 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)",
                  string:srcaddr,
                  replace:"\1"); a4 = a4 % 255;

dstaddr = get_host_ip();

b1 = ereg_replace(pattern:"([0-9]*)\.[0-9]*\.[0-9]*\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b1 = b1 % 255;

b2 = ereg_replace(pattern:"[0-9]*\.([0-9]*)\.[0-9]*\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b2 = b2 % 255;


b3 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.([0-9]*)\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b3 = b3 % 255;

b4 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)",
                  string:dstaddr,
                  replace:"\1"); b4 = b4 % 255;

sendata = raw_string(
0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x02, 0x00, 0x00, a1,   a2,
a3,     a4, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x04,
b1,     b2,   b3,   b4, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x9F, 0x72, 0x6F, 0x6F, 0x74, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x72, 0x6F, 0x6F, 0x74, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
#  1     2     3     4     5     6     7     8     9     10

send(socket:soc, data:sendata);
result = recv(socket:soc, length:4096);
if (result)
{
  banner = "talkd protocol version: ";
  banner = string(banner, ord(result[0]));
  service_register(port: 518, ipproto: "udp", proto: "ntalk");
  log_message(port:518, data:banner, protocol:"udp");
}

close(soc);
