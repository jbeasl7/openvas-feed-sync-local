# SPDX-FileCopyrightText: 2008 Tenable Network Security / Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80059");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Firewall Enabled");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Tenable Network Security / Michel Arboi");
  script_family("Service detection");
  script_mandatory_keys("Host/scanners/openvas_tcp_scanner"); # This plugin only works if openvas_tcp_scanner has run

  script_tag(name:"summary", value:"Based on the responses obtained by the TCP scanner, it was possible to
  determine that the remote host seems to be protected by a firewall.

  Important: This plugin only works if OpenVAS TCP Scanner was used.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

if(!get_kb_item("Host/scanners/openvas_tcp_scanner"))
  exit(0); # This plugin only works if openvas_tcp_scanner has run

open = int(get_kb_item("TCPScanner/OpenPortsNb"));
closed = int(get_kb_item("TCPScanner/ClosedPortsNb"));
filtered = int(get_kb_item("TCPScanner/FilteredPortsNb"));

total = open + closed + filtered;

if(total == 0)
  exit(0);

if(filtered == 0)
  exit(0);

if(get_kb_item("TCPScanner/RSTRateLimit"))
  exit(0);

if(filtered > (closed * 4)) {
  log_message(port:0);
  set_kb_item(name:"Host/firewalled", value:TRUE);
}

exit(0);
