# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105776");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-06-22 11:05:14 +0200 (Wed, 22 Jun 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Veeam Backup & Replication Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");

  # Covered in new gsf/gb_veeam_backup_replication_server_http_detect.nasl (OID: 1.3.6.1.4.1.25623.1.0.152385)
  script_tag(name:"summary", value:"HTTP based detection of Veeam Backup & Replication");

  script_xref(name:"URL", value:"https://www.veeam.com/vm-backup-recovery-replication-software.html");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
