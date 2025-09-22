# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116486");
  script_version("2023-04-04T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-04 10:19:20 +0000 (Tue, 04 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-03-28 13:59:00 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: BSI TR-02102-4 Key Exchange Methods");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"diffie-hellman-group-exchange-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,rsa2048-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256", id:1);

  script_xref(name:"URL",value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"URL",value:"https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html");
  script_xref(name:"Policy", value:"BSI TR-02102-4: Key Exchange Methods");


  script_tag(name:"summary", value:"When establishing the SSH connection, keys are exchanged in order to create and
exchange shared session keys for authentication and encryption.

The following key exchange methods are recommended: diffie-hellman-group-exchange-sha256,
diffie-hellman-group14-sha256, diffie-hellman-group15-sha512, diffie-hellman-group16-sha512,
rsa2048-sha256, ecdh-sha2-*

Note: For rsa2048-sha256 it is recommended that the key length is at least 2000 bits to remain
compliant through 2023.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^KexAlgorithms' /etc/ssh/sshd_config";
title = "SSH KexAlgorithms";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/kexalgorithms");
  if(!value){
    value = "Error";
    compliant = "incomplete";
    comment = "Unable to retrieve supported KexAlgorithms from /etc/ssh/sshd_config";
  }else{
    compliant = "yes";

    foreach kexalgorithm(policy_build_list_from_string(str:value)){
      if(kexalgorithm >!< default){
        compliant = "no";
      }
    }
  }
}

policy_reporting(result:value,default:default,compliant:compliant,fixtext:solution,
  type:test_type,test:cmd,info:comment);
policy_set_kbs(type:test_type,cmd:cmd,default:default,solution:solution,title:title,
  value:value,compliant:compliant);

exit(0);
