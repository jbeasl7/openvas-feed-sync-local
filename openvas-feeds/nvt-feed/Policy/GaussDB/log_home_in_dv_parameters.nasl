# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150215");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-15 14:37:07 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Audit File Path");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_dv_parameters.nasl", "read_gsdb_data_permissions.nasl");
  script_mandatory_keys("Compliance/Launch");

  # Keep script_preference, even though not used anymore. Scanner would break otherwise.
  script_add_preference(name:"Value", type:"entry", value:"/home/gaussdba/data/log", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"The LOG_HOME parameter specifies the storage path of the audit
file. By default, the audit file is stored in the ${GSDB_DATA}/log/audit directory.

Note: The script compares the LOG_HOME in DV_PARAMETERS with the ${GSDB_DATA}/log environmental variable.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME, VALUE FROM DV_PARAMETERS WHERE NAME = 'LOG_HOME';";
title = "Audit File Path";
solution = "Change the value of LOG_HOME in ${GSDB_DATA}/cfg/zengine.ini, or run
'ALTER SYSTEM SET LOG_HOME = FILE_PATH SCOPE=PFILE;'";
test_type = "SQL_Query";
default = "${GSDB_DATA}/log";

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!default = get_kb_item("Policy/zsql/dv_parameters/LOG_HOME/value")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not find value for LOG_HOME in table DV_PARAMETERS";
}else if(!gsdb_data_log = get_kb_item("Policy/linux/${GSDB_DATA}/log/stat")){
  value = "error";
  compliant = "incomplete";
  comment = "Can not find value for ${GSDB_DATA}/log";
}else{
  file_egrep = egrep(string:gsdb_data_log, pattern:"File:");
  file = eregmatch(string:file_egrep, pattern:"File:[^/]+([a-z,A-Z,_,/,-,.,0-9]*)");

  if(!file){
    compliant = "incomplete";
    comment = "Can not find value for ${GSDB_DATA}/log";
  }else{
    value = chomp(file[1]);
    if(default >< value)
      compliant = "yes";
    else
      compliant = "no";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
