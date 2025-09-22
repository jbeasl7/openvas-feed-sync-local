# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10335");
  script_version("2023-06-22T10:34:14+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:14 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenVAS TCP scanner");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("host_alive_detection.nasl");

  script_timeout(4*360);

  script_tag(name:"summary", value:"This plugin is a classical TCP port scanner.
It shall be reasonably quick even against a firewalled target.

Once a TCP connection is open, it grabs any available banner
for the service identification plugins

Note that TCP scanners are more intrusive than
SYN (half open) scanners.");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

plugin_run_openvas_tcp_scanner();
