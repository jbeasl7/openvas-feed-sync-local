# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103633");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-01-04 12:11:14 +0100 (Fri, 04 Jan 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detection of Rugged Operating System");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");

  script_tag(name:"summary", value:"Detection of Rugged Operating System.
  The script sends a connection request to the server and attempts to
  extract the version number from the reply.

  This VT has been deprecated and replaced by the VT 'Siemens RUGGEDCOM / Rugged Operating System Detection Consolidation'
  (OID: 1.3.6.1.4.1.25623.1.0.140811).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
