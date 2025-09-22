# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100429");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2010-01-06 18:07:55 +0100 (Wed, 06 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Movable Type Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");

  script_tag(name:"summary", value:"Detection of Movable Type.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.

  This VT has been deprecated and merged into the VT 'Movable Type Detection (HTTP)'
  (OID: 1.3.6.1.4.1.25623.1.0.113643).");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
