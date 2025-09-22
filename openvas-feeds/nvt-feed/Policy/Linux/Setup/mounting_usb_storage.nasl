# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150112");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-01-30 14:21:00 +0100 (Thu, 30 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Mounting of usb-storage filesystems");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_modprobe_files.nasl", "read_lsmod_kernel_modules.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Disabled;Enabled", id:1);

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.1.23 Disable USB Storage (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 1.1.23 Disable USB Storage (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.5 Configure Devices Not To Auto-run Content");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.4 Configure Anti-Malware Scanning of Removable Devices");

  script_tag(name:"summary", value:"USB storage devices such as thumb drives can be used to
introduce unauthorized software and other vulnerabilities. Support for these devices should be
disabled and the devices themselves should be tightly controlled.

Note: This script looks for entry 'install usb-storage /bin/true' in files in /etc/modprobe.d/*.conf and
if the module is loaded via lsmod command.");

  exit(0);
}

include("policy_functions.inc");

cmd = "lsmod; grep -r 'install usb-storage /bin/true' /etc/modprobe.d/*";
title = "Mounting of usb-storage filesystems";
solution = "Add or remove 'install usb-storage /bin/true' in config file (/etc/modprobe.d/*.conf) and run modprobe [-r] usb-storage";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);
default = "Disabled";
comment = "";

if(get_kb_item("Policy/linux//etc/modprobe.d/ERROR") || get_kb_item("Policy/linux/lsmod/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else if(get_kb_item("Policy/linux//etc/modprobe.d/NO_BASH")){
  value = "Error";
  compliant = "incomplete";
  comment = "Bash is not available on the target host but needed for this test.";
}else{
  if(get_kb_item("Policy/linux/module/usb-storage"))
    loaded = TRUE;

  foreach file (get_kb_list("Policy/linux//etc/modprobe.d")){
    if(get_kb_item("Policy/linux/" + file + "/content/ERROR"))
      continue;
    file_content = get_kb_item("Policy/linux/" + file + "/content");
    if(egrep(string:file_content, pattern:"^\s*install usb-storage /bin/true"))
      deactivated = TRUE;
  }

  if(loaded || !deactivated)
    value = "Enabled";
  else
    value = "Disabled";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
