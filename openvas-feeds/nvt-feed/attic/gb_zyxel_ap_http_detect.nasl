# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142867");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-09-10 02:16:55 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zyxel Access Point Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Zyxel Access Points.

  This VT has been deprecated and replaced by specific detection for various Zyxel devices (e.g. USG, NXC, WAC,
  etc.).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");

  script_xref(name:"URL", value:"https://www.zyxel.com/products_services/smb-wlan_aps_and_controllers.shtml?t=c");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
