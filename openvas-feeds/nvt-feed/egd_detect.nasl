# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18393");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("EGD detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_require_ports("Services/unknown", 8000);
  script_dependencies("find_service1.nasl", "find_service2.nasl");

  script_tag(name:"solution", value:"If this service is not needed, disable it or filter incoming traffic
to this port.");

  script_tag(name:"summary", value:"A random number generator is listening on the remote port.

Description :

The Entropy Gathering Daemon is running on the remote host.
EGD is a user space random generator for operating systems
that lack /dev/random");

  script_xref(name:"URL", value:"http://egd.sourceforge.net/");

  exit(0);
}

include("host_details.inc");
include("global_settings.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:8000 );

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0'); # get
r = recv(socket: s, length: 16);
close(s);
if (strlen(r) != 4) exit(0);
entropy = 0;
for (i = 0; i <= 3; i ++)
 entropy = (entropy << 8) | ord(r[i]);

debug_print('entropy=', entropy, '\n');

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\x01\x07'); # Read 7 bytes of entropy
r = recv(socket: s, length: 16);
close(s);
n = ord(r[0]);
if (strlen(r) != n + 1) exit(0);
debug_print('EGD gave ', n, 'bytes of entropy (7 requested)\n');

service_register(port: port, proto: 'egd');
log_message(port);
