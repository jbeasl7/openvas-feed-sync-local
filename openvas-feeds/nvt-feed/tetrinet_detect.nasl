# SPDX-FileCopyrightText: 2006 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19608");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Tetrinet server detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("Copyright (C) 2006 Michel Arboi");
  script_family("Service detection");
  script_require_ports("Services/unknown", 31457);
  script_dependencies("find_service.nasl", "find_service2.nasl");

  script_tag(name:"summary", value:"The remote host runs a Tetrinet game server on this port. Make
  sure the use of this software is done in accordance to your security policy.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

c = '00469F2CAA22A72F9BC80DB3E766E7286C968E8B8FF212\xff';

port = unknownservice_get_port( default:31457 );

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data:c);
b = recv(socket: s, length: 1024);
if ( ! b ) exit(0);
if (match(string: b, pattern: 'winlist *'))
{
 log_message(port: port);
 service_register(port: port, proto: 'tetrinet');
}
