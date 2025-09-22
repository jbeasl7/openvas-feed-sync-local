# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150125");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-02-04 12:02:45 +0100 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read /etc/login.defs (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/login.defs");

  script_tag(name:"summary", value:"The /etc/login.defs file defines the site-specific configuration
for the shadow password suite. This file is required. Absence of this file will not prevent system
operation, but will probably result in undesirable operation.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

file = "/etc/login.defs";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/" + file + "/ERROR", value:TRUE);
  set_kb_item(name:"Policy/linux/" + file + "/stat/ERROR", value:TRUE);
  exit(0);
}

policy_linux_stat_file(socket:sock, file:file);
policy_linux_file_content(socket:sock, file:file);

exit(0);