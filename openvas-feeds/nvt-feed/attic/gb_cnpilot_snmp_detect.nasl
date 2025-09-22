# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140186");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-03-14 17:03:28 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detect (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Cambium Networks cnPilot.

  This VT has been deprecated and replaced by the VT 'Cambium Networks cnPilot Detection' (OID: 1.3.6.1.4.1.25623.1.0.140629).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
