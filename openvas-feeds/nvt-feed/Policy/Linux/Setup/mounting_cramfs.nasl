# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109714");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-09 08:27:13 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Mounting of cramfs filesystems");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_lsmod_kernel_modules.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Disabled;Enabled", id:1);

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");

  script_tag(name:"summary", value:"The cramfs filesystem type is a compressed read-only Linux
filesystem embedded in small footprint systems. A cramfs image can be used without having to first
decompress the image.

Removing support for unneeded filesystem types reduces the local attack surface of the server. If
this filesystem type is not needed, disable it.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");

cmd = "modprobe -n -v cramfs; lsmod | grep cramfs";
title = "Mounting of cramfs filesystems";
solution = "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:
'install cramfs /bin/true'.
Run the following command to unload the cramfs module: 'rmmod cramfs'.";
test_type = "SSH_Cmd";
default = script_get_preference( "Status", id:1 );

if( ! modprobe = policy_modprobe( module:"cramfs" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run modprobe command on host";
}else if( get_kb_item( "Policy/linux/lsmod/ERROR" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run lsmod command on host";
}else{
  if( get_kb_item("Policy/linux/module/cramfs" ) ) {
    loaded = TRUE;
    comment = "Kernel module cramfs loaded. ";
  }

  if( modprobe !~ "install /bin/true" ){
    no_install_redirect = TRUE;
    comment += "Kernel module cramfs is not configured to run '/bin/true'.";
  }

  if(loaded || no_install_redirect)
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
