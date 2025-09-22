# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108083");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-02-19 16:08:05 +0100 (Sun, 19 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Launch Nmap NSE net Tests");
  script_category(ACT_INIT);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"This script controls the execution of Nmap NSE net Tests");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
