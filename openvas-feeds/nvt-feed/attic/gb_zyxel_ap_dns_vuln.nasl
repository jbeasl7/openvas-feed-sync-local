# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142868");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-09-10 03:01:53 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zyxel Gateway / Access Point External DNS Request Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Some Zyxel Access Points are prone to an information disclosure
  vulnerability where external DNS requests can be made.

  This VT has been deprecated and replaced by various device specific VTs.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A DNS request can be made by an unauthenticated attacker to
  either spam a DNS service of a third party with requests that have a spoofed origin or probe
  whether domain names are present on the internal network behind the firewall.");

  script_tag(name:"impact", value:"The vulnerability could allow an unauthenticated individual to
  spam an internal service or probe whether domain names are present on the internal network behind
  the firewall, which could result in internal DNS information disclosure.");

  script_tag(name:"affected", value:"Zyxel ATP200, ATP500, ATP800, UAG2100, UAG4100, USG20-VPN,
  USG20W-VPN, USG40, USG40W, USG60, USG60W, USG110, USG210, USG310, USG1100, USG1900, USG2200,
  VPN50, VPN100, VPN300, ZyWALL110, ZyWALL310, ZyWALL1100, NXC2500 and NXC5500.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.zyxel.com/support/web-CGI-vulnerability-of-gateways-and-access-point-controllers.shtml");
  script_xref(name:"URL", value:"https://sec-consult.com/en/blog/advisories/external-dns-requests-in-zyxel-usg-uag-atp-vpn-nxc-series/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
