# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105834");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-07-29 15:04:09 +0200 (Fri, 29 Jul 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere Application Server Detection (GIOP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/giop", 9100);

  script_tag(name:"summary", value:"GIOP (General Inter-ORB Protocol) based detection of an
  IBM WebSphere Application Server.");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("port_service_func.inc");

function parse_result (data) {
  local_var data;
  local_var v, tmp;

  if (strlen(data) < 8)
    return FALSE;

  for (v = 0; v < strlen(data); v++) {
    if (isprint(c: data[v])) {
      tmp += data[v];
    } else {
      tmp += ' ';
    }
  }

  return tmp;
}

port = service_get_port(default: 9100, proto: "giop");

if (!soc = open_sock_tcp(port))
  exit(0);

giop_req = raw_string("GIOP",
                      0x01, 0x00,                        # Version
                      0x00,                              # Little Endian: False
                      0x00,                              # Message Type: Request
                      0x00, 0x00, 0x00, 0xe4,            # Message Size (228)
                      0x00, 0x00, 0x00, 0x02,            # Service Context List: Sequence Length
                      0x00, 0x00, 0x00, 0x06,            #  Service Context: VSCID and SCID
                      0x00, 0x00, 0x00, 0xa0,            #   Sequence Length
                      0x00,                              #   Endianness: Big Endian
                      0x00, 0x00, 0x00, 0x00, 0x00,      #   Context Data
                      0x00, 0x28, "IDL:omg.org/SendingContext/CodeBase:1.0",
                      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 0x02,
                      0x00, 0x00, 0x00, 0x00, 0x0e,
                      "192.168.2.136",
                      0x00, 0x04, 0x79, 0x00, 0x00, 0x00, 0x19, 0xaf,
                      0xab, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x02, 0x93,
                      0xbe, 0x05, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                      0x00, 0x00, 0x02, 0x05, 0x01, 0x00, 0x01, 0x00,
                      0x01, 0x00, 0x20, 0x00, 0x01, 0x01, 0x09, 0x00,
                      0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00,
                      0x4e, 0x45, 0x4f, 0x00,            #  Service Context: VSCID and SCID
                      0x00, 0x00, 0x00, 0x02,            #   Sequence Length
                      0x00,                              #   Endianness: Big Endian
                      0x0a,                              #   Context Data
                      0x00, 0x00,
                      0x00, 0x00, 0x00, 0x05,            # Request ID
                      0x01,                              # Response expected
                      0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x04,            # Object Key Length
                      0x49, 0x4e, 0x49, 0x54,            # Object Key
                      0x00, 0x00, 0x00, 0x04,            # Operation length
                      "get", 0x00,                       # Request operation
                      0x00, 0x00, 0x00, 0x00,            # Requesting Principal Length
                      0x00, 0x00, 0x00, 0x0c,            # Stub data
                      "NameService", 0x00);

send(socket: soc, data: giop_req);
data = recv(socket: soc, length: 4096);

close(soc);

if (!data || "WebSphere" >!< data)
  exit(0);

version = "unknown";

set_kb_item(name: "ibm/websphere_or_liberty/detected", value: TRUE);
set_kb_item(name: "ibm/websphere/detected", value: TRUE);
set_kb_item(name: "ibm/websphere_or_liberty/giop/detected", value: TRUE);
set_kb_item(name: "ibm/websphere_or_liberty/giop/port", value: port);

data = parse_result(data: data);

vers = eregmatch(pattern: "IBM WebSphere Application Server( Network Deployment|\s*\-\s*ND)?\s*([0-9.]+[^ ]+)",
                 string: data);
if (!isnull(vers[2])) {
  version = vers[2];
  set_kb_item(name: "ibm/websphere_or_liberty/giop/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "ibm/websphere_or_liberty/giop/" + port + "/version", value: version);

exit(0);
