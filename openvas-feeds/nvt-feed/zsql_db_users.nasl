# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150149");

  script_version("2023-07-28T16:09:08+0000");

  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-03-09 12:37:56 +0000 (Mon, 09 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Content of DB_USERS Database");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"This script writes the complete database of DB_USERS to KB.

Note: this script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/zsql/zsql_db_users/ssh/ERROR", value:TRUE);
  exit(0);
}

query = 'dump table DB_USERS into file \'STDOUT\' COLUMNS TERMINATED BY \'|\';';
db_users = zsql_command(socket:sock, query:query);

if(!db_users){
  set_kb_item(name:"Policy/zsql/zsql_db_users/ERROR", value:TRUE);
}else{
  foreach line(split(db_users, keep:FALSE)){
    if(line=~"SQL> "){
      line = str_replace(string:line, find:"SQL> ", replace:"");
    }
    items = eregmatch(string:line, pattern:"(.*)\|(.*)\|(.*)\|(.*)");
    if(items){
      set_kb_item(name:"Policy/zsql/zsql_db_users/username/"+items[1] , value:items[2]);
      set_kb_item(name:"Policy/zsql/zsql_db_users/created/"+items[1], value:items[3]);
      set_kb_item(name:"Policy/zsql/zsql_db_users/cryptoperiod/"+items[1], value:items[4]);
    }else{
      set_kb_item(name:"Policy/zsql/zsql_db_users/empty", value:TRUE);
    }
  }
}

exit(0);
