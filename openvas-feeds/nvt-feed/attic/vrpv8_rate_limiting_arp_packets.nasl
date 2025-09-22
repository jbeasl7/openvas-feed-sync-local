# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150300");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-07-21 12:53:49 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("Huawei Data Communication: Configuring Rate Limiting for ARP Packets (Deprecated)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");

  script_tag(name:"summary", value:"This VT has been deprecated and replaced by the following VT:

  - 'Huawei Data Communication: Configuring ARP Packet Rate Limiting' (OID: 1.3.6.1.4.1.25623.1.0.150258)");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
