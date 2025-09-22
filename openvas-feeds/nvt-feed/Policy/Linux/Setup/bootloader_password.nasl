# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109733");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-15 08:27:43 +0100 (Tue, 15 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: GRUB bootloader password");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_boot_grub_config_files.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Password protection", type:"radio", value:"Enabled;Disabled", id:1);

  script_xref(name:"URL", value:"https://www.techrepublic.com/article/how-to-password-protect-your-grub-menu/");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.4.2 Ensure bootloader password is set (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 1.5.2 Ensure bootloader password is set (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");

  script_tag(name:"summary", value:"GRUB is the bootloader mainly used on Linux systems. If
protected with a password, users can not enter or change boot parameters without a password.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'password' /boot/*/menu.lst /boot/*/user.cfg /boot/*/grub.cfg";
title = "Password protected GRUB bootloader";
solution = "Run 'grub-md5-crypt', 'grub2-setpassword' or 'grub-mkpasswd-pbkdf2',
copy password hash to grub config file (begin line with 'password' or 'password_pbkdf2'), run 'update-grub'";
test_type = "SSH_Cmd";
default = script_get_preference("Password protection", id:1);

if(get_kb_item("Policy/linux/grub/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/sysconfig/init/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/sysconfig/init";
}else{
  grub_config_files = get_kb_list("Policy/linux/grub/files/*");
  comment = "Files: ";
  foreach file (grub_config_files){
    if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
      continue;

    read_file = TRUE;
    comment += ", " + file;
    content = get_kb_item("Policy/linux/" + file + "/content");
    grep = egrep(string:content, pattern:"password", icase:TRUE);
    foreach line (split(grep)){
      if(line =~ "^\s*password --md5" || line =~ "^\s*password_pbkdf2" || line =~ "^\s*GRUB2_PASSWORD=")
        value = "Enabled";
    }
  }

  if(!read_file){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not read any GRUB config file";
  }else if(!value){
    value = "Disabled";
  }

  compliant = policy_setting_exact_match(value:value, set_point:default);
  comment = str_replace(string:comment, find:", ", replace:"", count:1);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
