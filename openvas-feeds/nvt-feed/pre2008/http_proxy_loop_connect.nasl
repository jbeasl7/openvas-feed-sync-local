# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17154");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Proxy accepts CONNECT requests to itself");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "proxy_use.nasl");
  script_require_keys("Proxy/usage");
  script_require_ports("Services/http_proxy", 8080);

  script_tag(name:"solution", value:"reconfigure your proxy so that it
  refuses CONNECT requests to itself.");

  script_tag(name:"summary", value:"The proxy allows the users to perform
  repeated CONNECT requests to itself.

  Note that if the proxy limits the number of connections from a single IP (e.g. acl maxconn with Squid),
  it is protected against saturation and you may ignore this alert.");

  script_tag(name:"impact", value:"This allow anybody to saturate the proxy CPU, memory or
  file descriptors.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:8080, proto:"http_proxy");

if (! COMMAND_LINE)
{
 proxy_use = get_kb_item("Proxy/usage");
 if (! proxy_use) exit(0);
}

host = get_host_name();

soc = open_sock_tcp(port);

if (! soc)
  exit(0);

cmd = strcat('CONNECT ', host, ':', port, ' HTTP/1.0\r\n\r\n');
for (i = 3; i >= 0; i --)
{
 send(socket:soc, data: cmd);
 repeat
   line = recv_line(socket:soc, length:4096);
 until (! line || line =~ '^HTTP/[0-9.]+ ');
 if (line !~ '^HTTP/[0-9.]+ +200 ') break; # Also exit loop on EOF
}

close(soc);
if (i < 0) {
  security_message(port:port);
  exit(0);
}

exit(99);
