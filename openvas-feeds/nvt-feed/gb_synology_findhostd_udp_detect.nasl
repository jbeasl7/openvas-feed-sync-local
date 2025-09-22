# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153084");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-12 07:54:23 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology findhostd Detection (UDP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Service detection");
  script_dependencies("global_settings.nasl");
  script_require_udp_ports(9997, 9998, 9999);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"UDP based detection of services supporting findhost protocol
  as used by the Synology Assistant.");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("host_details.inc");
include("pcap_func.inc");
include("port_service_func.inc");
include("version_func.inc");

# Currently only on IPv4
if (TARGET_IS_IPV6())
  exit(0);

port_list = make_list(9997, 9998, 9999);

ownip = this_host();
targetip = get_host_ip();
mac = get_local_mac_address_from_ip(ownip);
if (isnull(mac))
  exit(0);

msg = raw_string(0x12, 0x34, 0x56, 0x78, "SYNO",       # Service Magic
                 0xa4,                                 # TLV type (unknown)
                 0x04,                                 #   Length
                 0x00, 0x00, 0x02, 0x01,               #   Value: (0x01020000)
                 0xa6,                                 # TLV type (unknown)
                 0x04,                                 #   Length
                 0x78, 0x00, 0x00, 0x00,               #   Value: (0x00000078)
                 0x01,                                 # TLV type (Packet Type)
                 0x04,                                 #   Length
                 0x01, 0x00, 0x00, 0x00,               #   Value: (0x00000001)
                 0xb0,                                 # TLV type (unknown)
                 0x08,                                 #   Length
                 0xc0, 0x01, 0x00, 0x00,               #   Value: (c001000000000000)
                 0x00, 0x00, 0x00, 0x00,
                 0xb1,                                 # TLV type (unknown)
                 0x08,                                 #   Length
                 0x00, 0x00, 0x00, 0x00,               #   Value: 0
                 0x00, 0x00, 0x00, 0x00,
                 0xb8,                                 # TLV type (unknown)
                 0x08,                                 #   Length
                 0xc0, 0x01, 0x00, 0x00,               #   Value: (c001000000000000)
                 0x00, 0x00, 0x00, 0x00,
                 0xb9,                                 # TLV type (unknown)
                 0x08,                                 #   Length
                 0x00, 0x00, 0x00, 0x00,               #   Value: 0
                 0x00, 0x00, 0x00, 0x00,
                 0x7c,                                 # TLV type (Mac Address)
                 mkbyte(strlen(mac)),                  #   Length
                 mac);                                 #   Value: generated MAC address

foreach port (port_list) {
  if (!get_udp_port_state(port))
    continue;

  if (!soc = open_sock_udp(port))
    continue;

  filter = "src host " + targetip + " and dst host 255.255.255.255 and udp and dst port " + port;

  recv = pcap_tcp_udp_send_recv(port: port, data: msg, proto: "udp", pcap_filter: filter);

  close(soc);

  if (isnull(recv) || hexstr(recv) !~ "^1234567853594E4F" || hexstr(recv) == hexstr(msg))
    continue;

  set_kb_item(name: "synology/findhostd/detected", value: TRUE);
  set_kb_item(name: "synology/findhostd/" + port + "/response", value: recv);

  service_register(port: port, proto: "findhostd", ipproto: "udp");

  log_message(port: port, proto: "udp", data: "A Synology findhostd service is running at this port.");
}

exit(0);
