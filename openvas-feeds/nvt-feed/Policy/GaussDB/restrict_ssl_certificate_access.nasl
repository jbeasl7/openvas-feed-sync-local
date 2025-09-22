# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150271");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-06-18 12:30:29 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB: Restricting the Permission for the SSL Private Key");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_add_preference(name:"Value", type:"entry", value:"400", id:1);

  script_tag(name:"summary", value:"If SSL is used, you need to configure the SSL certificate on the
database server. You are advised to set the permission for the private key file to owner-readable-only.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");

title = "Restricting the Permission for the SSL Private Key";
cmd = "SELECT VALUE FROM DV_PARAMETERS WHERE NAME = 'SSL_KEY'; stat SSL_KEY";
solution = "Configure SSL_KEY permissions as needed.";
test_type = "SQL_Query";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!ssl_key = get_kb_item("Policy/zsql/dv_parameters/SSL_KEY/value")){
  compliant = "yes";
  value = "None";
  comment = "No SSL key used";
}else{
  comment = "SSL key file path: " + ssl_key;
  if(!sock = ssh_login_or_reuse_connection()){
    compliant = "incomplete";
    value = "error";
    comment = "SSL key is used, but no SSH connection to host possible. " + comment;
  }else{
    policy_linux_stat_file(socket:sock, file:ssl_key);
    if(!stat = get_kb_item("Policy/linux/" + ssl_key + "/stat")){
      compliant = "incomplete";
      value = "error";
      comment = "SSL key is used, but can not get the access rights to file: " + ssl_key;
    }else{
      value = policy_get_access_permissions(stat:stat);
      compliant = policy_access_permissions_match_or_stricter(value:value, set_point:default);
    }
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
