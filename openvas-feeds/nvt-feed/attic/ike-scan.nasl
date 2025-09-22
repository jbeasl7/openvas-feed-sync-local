# SPDX-FileCopyrightText: 2008 Tim Brown and Vlatko Kosturjak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80000");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2002-1623");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-08-31 23:34:05 +0200 (Sun, 31 Aug 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ike-scan (NASL wrapper)");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("Copyright (C) 2008 Tim Brown and Vlatko Kosturjak");

  script_tag(name:"summary", value:"This VT is deprecated.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
