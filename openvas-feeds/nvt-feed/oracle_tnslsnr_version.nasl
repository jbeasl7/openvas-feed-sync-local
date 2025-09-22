# SPDX-FileCopyrightText: 2005 James W. Abendschan <jwa@jammed.com>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10658");
  script_version("2024-10-29T05:05:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:46 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Oracle Database Detection (TNS service)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 James W. Abendschan <jwa@jammed.com>");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  # nb: Oracle is using 1521 as the default port but the one registered with
  # IANA is 1527 (see e.g. http://www.dba-oracle.com/t_listener_port_numbers.htm)
  # so we're using both here.
  script_require_ports("Services/unknown", 1521, 1527);

  script_tag(name:"summary", value:"TNS service based detection of an Oracle Database Server");

  script_tag(name:"vuldetect", value:"This script sends 'CONNECT_DATA=(COMMAND=VERSION)' command via
  Oracle tnslsnr, a network interface to the remote Oracle database and try to get the version from
  the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("port_service_func.inc");
include("list_array_func.inc");

function tnscmd(sock, command) {

  local_var sock, command;
  local_var command_length, packet_length, plen_h, plen_l, clen_h, clen_l, packet;

  command_length = strlen(command);
  packet_length = command_length + 58;

  # packet length - bytes 1 and 2
  plen_h = packet_length / 256;
  plen_l = 256 * plen_h; # bah, no ( ) ?
  plen_l = packet_length - plen_h;

  clen_h = command_length / 256;
  clen_l = 256 * clen_h;
  clen_l = command_length - clen_l;

  packet = raw_string(plen_h, plen_l,                   # Packet Length
                      0x00, 0x00,                       # Packet Checksum
                      0x01,                             # Packet Type (Connect)
                      0x00,                             # Reserved
                      0x00, 0x00,                       # Header Checksum
                      0x01, 0x36,                       # Version (310)
                      0x01, 0x2c,                       # Compatible Version (300)
                      0x00, 0x00,                       # Service Options
                      0x08, 0x00,                       # Session Data Unit Size (32768)
                      0x7f, 0xff,                       # Maximum Transmission Data Unit Size (32767)
                      0x7f, 0x08,                       # NT Protocol Characteristics
                      0x00, 0x00,                       # Line Turnaround Value
                      0x00, 0x01,                       # Value of 1 in Hardware
                      clen_h, clen_l,                   # Length of Connect Data
                      0x00, 0x3a,                       # Offset to Connect Data
                      0x00, 0x00, 0x00, 0x00,           # Maximum Receivable Connect Data
                      0x00,                             # Connect Flags 0
                      0x00,                             # Connect Flags 1
                      0x00, 0x00, 0x00, 0x00,           # Trace Cross Facility Item 1
                      0x00, 0x00, 0x00, 0x00,           # Trace Cross Facility Item 2
                      0x00, 0x00, 0x34, 0xe6,           # Trace Unique Connection ID
                      0x00, 0x00, 0x00, 0x01,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, command);

  send(socket: sock, data: packet);
}

# Reply comes in 2 packets.  The first is the reply to the connection
# request, and if that is successful, the second contains the reply to
# the version request.
#
# The TNS packets come with a 8 byte header and the header contains
# the packet length.  The first 2 bytes of the header are the total
# length of the packet in network byte order.
#
# Steven Procter, Nov 11 2002

function extract_version(socket, port) {

  local_var socket, port;
  local_var header, report, tot_len, remaining, rest, flags, version;

  header = recv(socket: socket, length: 8, timeout: 5);
  if (strlen(header) < 5)
    return 0;

  if (ord(header[4]) == 4) {
    report = string("A TNS service is running on this port but it refused to honor an attempt to connect to it.\n\n",
                    "The TNS reply code was: ", ord(header[4]));
    service_register(port: port, proto: "oracle_tnslsnr");
    log_message(port: port, data: report);
    return 0;
  }

  if (ord(header[4]) != 2)
    return 0;

  # read the rest of the accept packet
  tot_len = getword(blob: header);
  remaining = tot_len - 8;
  if (remaining < 0)
    return 0;

  rest = recv(socket: socket, length: remaining, timeout: 5);

  # next packet should be of type data and the data contains the version string
  header = recv(socket: socket, length: 8, timeout: 5);
  if (strlen(header) < 5 || ord(header[4]) != 6)
    return 0;

  tot_len = getword(blob: header);

  # first 2 bytes of the data are flags, the rest is the version string.
  remaining = tot_len - 8;
  if (remaining < 0)
    return 0;

  flags = recv(socket: socket, length: 2, timeout: 5);
  version = recv(socket: socket, length: remaining - 2, timeout: 5);
  return version;
}

function oracle_version(port) {

  local_var port;
  local_var sock, cmd, version, ver, cpe;

  sock = open_sock_tcp(port);
  if (sock) {
    cmd = "(CONNECT_DATA=(COMMAND=VERSION))";
    tnscmd(sock: sock, command: cmd);
    version = extract_version(socket: sock, port: port);
    close(sock);
    if (version == 0)
      return 0;

    # Version 19.0.0.0.0
    # Version 12.1.0.2.0
    # Version 11.1.0.7.0
    # Version 10.2.0.1.0
    # Version 9.2.0.4.0
    # Version 8.1.7.2.0
    # Version 8.1.6.0.0
    ver = eregmatch(pattern: "Version ([0-9.]+)", string: version);
    if (isnull(ver[1]))
      return 0;

    service_register(port: port, proto: "oracle_tnslsnr");
    # n.b. used in gb_database_open_access_vuln.nasl
    set_kb_item(name: "oracle_tnslsnr/" + port + "/version", value: ver[1]);
    set_kb_item(name: "OpenDatabase/found", value: TRUE);

    set_kb_item( name: "oracle/database/detected", value: TRUE );
    set_kb_item( name: "oracle/database/tnslsnr/detected", value: TRUE );
    set_kb_item( name: "oracle/database/tnslsnr/port", value: port );
    set_kb_item( name: "oracle/database/tnslsnr/" + port + "/installs",
                 value:port + "#---#" + port + "/tcp" +"#---#" + ver[1] + "#---#" + ver[0] );
  }
}

ports = unknownservice_get_ports(default_port_list: make_list(1521, 1527, 1522));
foreach port(ports)
  oracle_version(port: port);

exit(0);
