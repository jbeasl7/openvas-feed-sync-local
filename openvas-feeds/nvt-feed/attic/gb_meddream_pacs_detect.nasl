# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141472");
  script_version("2025-08-05T05:45:17+0000");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-09-12 16:07:21 +0700 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MedDream PACS Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of MedDream PACS Server.

  The script sends a connection request to the server and attempts to detect MedDream PACS Server.

  This VT has been deprecated and replaced by the VT
  'MedDream PACS Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.155091).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");

  script_xref(name:"URL", value:"https://www.softneta.com/products/meddream-pacs-server/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
