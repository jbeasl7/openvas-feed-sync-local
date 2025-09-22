# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116488");
  script_version("2023-04-18T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:19:20 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 11:00:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: BSI TR-02102-4 Encryption Algorithms");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"AEAD_AES_128_GCM,AEAD_AES_256_GCM,aes128-ctr,aes192-ctr,aes256-ctr", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"BSI TR-02102-4: 3.4 Encryption Algorithms");

  script_tag(name:"summary", value:"Recommended SSH encryption ciphers from TR-02102-4.
  Per the recommendations, AEAD_AES_128_GCM or AEAD_AES_256_GCM should be utilized when possible.

  Note: This check fails if any algorithms are found that are not specified in the VT preferences.
  The default list is based on the recommendations.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^Ciphers' /etc/ssh/sshd_config";
title = "BSI TR-02102-4 Encryption Algorithms";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("linux/mount/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/ciphers");
  if(!value){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not get supported ciphers from /etc/ssh/sshd_config";
  }else{
    compliant = "yes";

    foreach cipher(policy_build_list_from_string(str:value)){
      if(cipher >!< default)
        compliant = "no";
        comment += cipher + '\n';
    }
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);