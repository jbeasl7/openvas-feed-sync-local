# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.115003");

  script_version("2023-07-28T16:09:08+0000");

  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-06 10:02:28 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Content of ROLE SYS PRIVS Database");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"This script writes the complete database of ROLE SYS PRIVS to KB.

  Note:This script stores values in KB only and has no output.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/zsql/zsql_role_sys_privs/ssh/ERROR", value:TRUE);
  exit(0);
}

query = 'dump table ROLE_SYS_PRIVS into file \'STDOUT\' COLUMNS TERMINATED BY \'|\';';
db_role_sys_privs = zsql_command(socket:sock, query:query);

if(!db_role_sys_privs){
  set_kb_item(name:"Policy/zsql/zsql_role_sys_privs/ERROR", value:TRUE);
}
foreach line(split(db_role_sys_privs, keep:FALSE)){
  if(line =~ "SQL>"){
    line = str_replace(string:line, find: "SQL> ", replace:"");
  }
  items = eregmatch(string:line, pattern:"(.*)\|(.*)\|(.*)");
  if(items){
    set_kb_item(name:"Policy/zsql/zsql_role_sys_privs/"+items[1]+"/"+items[2], value:items[3]);
  }else{
    set_kb_item(name:"Policy/zsql/zsql_role_sys_privs/empty", value:TRUE);
  }
}
exit(0);
