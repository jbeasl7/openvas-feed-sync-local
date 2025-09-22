# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146591");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2021-08-30 09:31:17 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("DNS Cache Snooping Vulnerability (UDP) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  # nb: The setting for get_3rdparty_domain() is currently located in smtp_settings.nasl.
  script_dependencies("dns_server.nasl", "global_settings.nasl", "smtp_settings.nasl");
  script_mandatory_keys("dns/server/udp/detected");
  script_require_udp_ports("Services/udp/domain", 53);
  script_exclude_keys("keys/islocalhost", "keys/is_private_lan");

  script_tag(name:"summary", value:"The DNS server is prone to a cache snooping vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted DNS query and checks the response.

  Notes:

  - No scan result is expected if localhost (127.0.0.1) was scanned (self scanning)

  - If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is disclosing information to this
  network please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"DNS cache snooping is when someone queries a DNS server in
  order to find out (snoop) if the DNS server has a specific DNS record cached, and thereby
  deduce if the DNS server's owner (or its users) have recently visited a specific site.

  This may reveal information about the DNS server's owner, such as what vendor, bank, service
  provider, etc. they use. Especially if this is confirmed (snooped) multiple times over a period.

  This method could even be used to gather statistical information - for example at what time does
  the DNS server's owner typically access his net bank etc. The cached DNS record's remaining TTL
  value can provide very accurate data for this.

  DNS cache snooping is possible even if the DNS server is not configured to resolve recursively
  for 3rd parties, as long as it provides records from the cache also to 3rd parties (a.k.a.
  'lame requests').");

  script_tag(name:"impact", value:"Attackers might gain information about cached DNS records
  which might lead to further attacks.

  Note: This finding might be an acceptable risk if you:

  - trust all clients which can reach the server

  - do not allow recursive queries from outside your trusted client network.");

  script_tag(name:"solution", value:"There are multiple possible mitigation steps depending on
  location and functionality needed by the DNS server:

  - Disable recursion

  - Don't allow public access to DNS Servers doing recursion

  - Leave recursion enabled if the DNS Server stays on a corporate network that cannot be reached
  by untrusted clients

  - If the risk is accepted either create an override for this result or configure the 'Private LAN'
  setting mentioned earlier");

  script_xref(name:"URL", value:"https://www.cs.unc.edu/~fabian/course_papers/cache_snooping.pdf");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-server-cache-snooping-attacks");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00509");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00482");

  exit(0);
}

# nb: No point in reporting on self scans via 127.0.0.1 as there is no information disclosure
# involved for these cases.
if (islocalhost())
  exit(0);

include("byte_func.inc");
include("port_service_func.inc");
include("smtp_func.inc");
include("network_func.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if (is_private_lan())
  exit(0);

port = service_get_port(default: 53, ipproto: "udp", proto: "domain");

if (!soc = open_sock_udp(port))
  exit(0);

dom = get_3rdparty_domain();

domain = split(dom, sep: ".", keep: FALSE);

payload = "";

i = 0;
foreach part (domain) {
  payload += raw_string(strlen(domain[i])) + domain[i];
  i++;
}

# Normal request to put/get it in the cache of the target DNS server
id = rand() % 65535;
req = raw_string(mkword(id),                   # Transaction ID
                 0x01, 0x00,                   # Flags (recursion desired)
                 0x00, 0x01,                   # Questions
                 0x00, 0x00,                   # Answer RRs
                 0x00, 0x00,                   # Authority RRs
                 0x00, 0x00,                   # Additional RRs
                 payload,                      # Query
                 0x00,
                 0x00, 0x01,                   # Type (Host Address)
                 0x00, 0x01);                  # Class (IN)

send(socket: soc, data: req);
recv = recv(socket: soc, length: 4096);
close(soc);
if (isnull(recv) || strlen(recv) < 8 || getword(blob: recv, pos: 6) == 0)
  exit(0);

if (!soc = open_sock_udp(port))
  exit(0);

id = rand() % 65535;
req = raw_string(mkword(id),                   # Transaction ID
                 0x00, 0x00,                   # Flags (do not query recursively)
                 0x00, 0x01,                   # Questions
                 0x00, 0x00,                   # Answer RRs
                 0x00, 0x00,                   # Authority RRs
                 0x00, 0x00,                   # Additional RRs
                 payload,                      # Query
                 0x00,
                 0x00, 0x01,                   # Type (Host Address)
                 0x00, 0x01);                  # Class (IN)

send(socket: soc, data: req);
recv = recv(socket: soc, length: 4096);
close(soc);

if (isnull(recv) || strlen(recv) < 8 || getword(blob: recv, pos: 6) == 0)
  exit(0);

report = 'Received (an) answer(s) for a non-recursive query for "' + dom + '".\n\nResult:\n\n';

pos = 24 + strlen(dom) + 6;

# Just extract the first one as it proves the point already
ip = ord(recv[pos]) + "." + ord(recv[pos + 1]) + "." + ord(recv[pos + 2]) + "." + ord(recv[pos + 3]);
report += ip;

security_message(port: port, data: report, proto: "udp");

exit(0);
