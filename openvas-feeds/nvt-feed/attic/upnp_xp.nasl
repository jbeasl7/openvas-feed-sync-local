# SPDX-FileCopyrightText: 2005 by John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10829");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0876");
  script_name("scan for UPNP hosts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 by John Lampe");
  script_family("Windows");

  script_xref(name:"URL", value:"http://grc.com/UnPnP/UnPnP.htm");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3723");

  script_tag(name:"summary", value:"Microsoft Universal Plug n Play is running on this machine. This service is dangerous for many
  different reasons.");

  script_tag(name:"solution", value:"To disable UPNP see the references.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE); # this check was replaced by gb_upnp_udp_detect.nasl (1.3.6.1.4.1.25623.1.0.103652)

  exit(0);
}

exit(66); # this check was replaced by gb_upnp_udp_detect.nasl (1.3.6.1.4.1.25623.1.0.103652)
