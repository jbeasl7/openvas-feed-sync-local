# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104000");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-05-31 15:59:37 +0200 (Tue, 31 May 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Launch Nmap for Network Scanning");
  script_category(ACT_SCANNER);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Port scanners");

  script_tag(name:"summary", value:"This script controls the execution of Nmap for network-wide
scanning. Depending on selections made, this may include port scanning, OS
detection, service detection and the execution of NSE tests.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
