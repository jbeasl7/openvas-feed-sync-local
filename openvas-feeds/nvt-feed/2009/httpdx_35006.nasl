# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100210");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("httpdx Multiple Commands Remote Buffer Overflow Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/httpdx/detected");

  script_tag(name:"summary", value:"The 'httpdx' program is prone to multiple remote buffer-overflow
  vulnerabilities because the application fails to perform adequate
  boundary-checks on user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code
  within the context of the affected application. Failed exploit
  attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"These issues affect httpdx 0.5b. Other versions may also be
  affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35006");

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
if(!banner || "httpdx" >!< banner)
  exit(0);

if(safe_checks()) {
  if(egrep(pattern:"httpdx 0.5 beta", string: banner)) {
    security_message(port:ftpPort);
    exit(0);
  }
} else {

   soc = open_sock_tcp(ftpPort);
   if(!soc)
     exit(0);

   user = crap(length: 100000);
   pass = "bla";

   ftp_log_in(socket:soc, user:user, pass:pass);
   close(soc);

   sleep(2);

   soc1 = open_sock_tcp(ftpPort);

   if(!soc1){
    security_message(port:ftpPort);
    exit(0);
  }
}

exit(0);
