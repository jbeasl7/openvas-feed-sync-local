# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150186");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-02 13:42:05 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB: Read Access Permissions for GSDB_DATA (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_tag(name:"summary", value:"The data directory stores user data files.

Access permissions to files and directories within {GSDB_DATA} need to be set carefully.

Note: This script only stores information for other Policy Controls. This script can be performed
only by a database installation user.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || ! sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/gaussdb/${GSDB_DATA}/ssh/ERROR", value:TRUE);
  exit(0);
}

if(gsdb_data = get_kb_item("Policy/gaussdb/gsdb_data")){
  files = make_list(gsdb_data + "/data", gsdb_data + "/cfg/zengine.ini", gsdb_data + "/log");
  foreach file (files){
    kb_name = ereg_replace(string:file, pattern:gsdb_data, replace:"${GSDB_DATA}");
    policy_linux_stat_file(socket:sock, file:file, kb_name:kb_name);
  }
}else{
  files = make_list("${GSDB_DATA}/data", "${GSDB_DATA}/cfg/zengine.ini", "${GSDB_DATA}/log");
  foreach file (files){
    policy_linux_stat_file(socket:sock, file:file);
  }
}

exit(0);