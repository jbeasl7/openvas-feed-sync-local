# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11540");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PPTP Server Buffer Overflow Vulnerability");
  script_cve_id("CVE-2003-0213");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_dependencies("pptp_detect.nasl");
  script_require_ports("Services/pptp", 1723);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7316");

  script_tag(name:"summary", value:"The remote PPTP server is prone to a remote buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks the response.");

  script_tag(name:"insight", value:"The problem occurs due to insufficient sanity checks when
  referencing user-supplied input used in various calculations. As a result, it may be possible for
  an attacker to trigger a condition where sensitive memory can be corrupted.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to
  execute arbitrary code with the privileges of the affected server.");

  script_tag(name:"solution", value:"The vendor has released updated releases of PPTP server which
  address this issue. Users are advised to upgrade as soon as possible.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("port_service_func.inc");

port = service_get_port(default:1723, proto:"pptp");

if(!soc = open_sock_tcp(port))
  exit(0);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

pptp_head = mkword(1) +           # Message Type
            mkdword(0x1a2b3c4d) + # Cookie
            mkword(1) +           # Control type (Start-Control-Connection-Request)
            mkword(0) +           # Reserved
            mkword(0x0100) +      # Protocol Version (1.0)
            mkword(0) +           # Reserved
            mkdword(1) +          # Framing Capabilities
            mkdword(1) +          # Bearer capabilities
            mkword(0);            # Maximum channels
pptp_vendor = mkword(2320) + # Firmware revision (arbitrary number)
              mkpad(64) +    # Hostname
              mkpad(64);     # Vendor

buffer = mkword(strlen(pptp_head) + strlen(pptp_vendor) + 2) + pptp_head + pptp_vendor;

send(socket:soc, data:buffer);
r = recv(socket:soc, length:2);
if(!r || strlen(r) != 2) {
  close(soc);
  exit(0);
}

l = getword(blob:r, pos:0);
r += recv(socket:soc, length:l - 2, min:l - 2);
close(soc);

if(strlen(r) != l)
  exit(0);

if(strlen(r) < strlen(pptp_head) + strlen(pptp_vendor))
  exit(0);

cookie = getdword(blob:r, pos:4);
if(cookie != 0x1a2b3c4d)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:buffer);
rec_buffer = recv(socket:soc, length:156);
close(soc);

if("linux" >!< rec_buffer)
  exit(0);

buffer = raw_string(0x00, 0x00) +     # Length = 0
         crap(length:1500, data:'A'); # Random data

if(!soc = open_sock_tcp(port))
  exit(0);

send(socket:soc, data:buffer);

# Patched pptp server will return RST(will not read bad data),
# unpatched will return FIN(read all the bad data and be overflowed).

filter = string("tcp and src host ", get_host_ip(), " and dst host ", this_host(), " and src port ", port, " and dst port ", get_source_port(soc), " and tcp[13:1]&1!=0");
for(i = 0; i < 5; i++) {
  r = pcap_next(pcap_filter:filter, timeout:2);
  if(r) {
    close(soc);
    security_message(port:port);
    exit(0);
  }
}

close(soc);

exit(99);