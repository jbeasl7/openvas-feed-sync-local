# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900244");
  script_version("2025-03-19T05:38:35+0000");
  script_cve_id("CVE-2008-3479");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-09 17:27:19 +0200 (Wed, 09 Jun 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Message Queuing (MSMQ) RCE Vulnerability (951071) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(2103);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31637");

  script_tag(name:"impact", value:"Successful exploitation could allow remote code execution by
  sending a specially crafted RPC request and can take complete control of an affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 2000 Service Pack 4 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to a boundary error when parsing RPC requests to the
  Message Queuing (MSMQ).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS08-065.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

port = 2103;
if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

## i.e fdb3a030-065f-11d1-bb9b-00a024ea5525 (MS-MQQM)
req = raw_string(0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
                 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                 0x30, 0xa0, 0xb3, 0xfd, 0x5f, 0x06, 0xd1, 0x11,
                 0xbb, 0x9b, 0x00, 0xa0, 0x24, 0xea, 0x55, 0x25,
                 0x01, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
                 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
                 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00);
send(socket:soc, data:req);
resp = recv(socket:soc, length:1024);
if(!resp || strlen(resp) < 14) {
  close(soc);
  exit(0);
}

## Packet type: 12 (Bind_ack) @ offset 2 - 1 byte
## Auth Length: 00 @ Offset 10 - 2 bytes
## Call ID : 00 @ Offset 12 - 4 bytes
if(!(resp[2] && ord(resp[2]) == 12 && resp[10] && ord(resp[10]) == 00 &&
   resp[11] && ord(resp[11]) == 00 && resp[12] && ord(resp[12]) == 00 &&
   resp[13] && ord(resp[13]) == 00 && resp[14] && ord(resp[14]) == 00 &&
   resp[15] && ord(resp[15]) == 00)) {
  close(soc);
  exit(0);
}

req = raw_string(0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                 0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00,
                 0x04, 0x00, 0x00, 0x00);
send(socket:soc, data:req);
resp = recv(socket:soc, length:1024);
close(soc);

## Packet Type : 2 (Response) @ offset 2
## After applying the patch
if(resp && strlen(resp) >= 55) {
  if(ord(resp[2]) == 02 && ord(resp[40]) == 50 && ord(resp[41]) == 00 &&
     ord(resp[42]) == 44 && ord(resp[43]) == 00 && ord(resp[44]) == 48 &&
     ord(resp[45]) == 00 && ord(resp[46]) == 44 && ord(resp[47]) == 00 &&
     (ord(resp[48]) == 54 || ord(resp[48]) == 55)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
