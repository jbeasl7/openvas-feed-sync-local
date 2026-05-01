# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140140");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Dell PowerProtect Data Domain Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/dell/powerprotect/data_domain/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Dell PowerProtect Data Domain.");

  exit(0);
}

include("ssh_func.inc");

if (!port = get_kb_item("ssh/login/dell/powerprotect/data_domain/port"))
  exit(0);

if (!uname = get_kb_item("ssh/login/dell/powerprotect/data_domain/" + port + "/uname"))
  exit(0);

version = "unknown";
model = "unknown";

set_kb_item(name: "dell/powerprotect/data_domain/detected", value: TRUE);
set_kb_item(name: "dell/powerprotect/data_domain/ssh-login/detected", value: TRUE);
set_kb_item(name: "dell/powerprotect/data_domain/ssh-login/port", value: port);

# Welcome to Data Domain OS 6.0.0.9-544198
# Welcome to Data Domain OS 8.6.1.10-1226405
vers = eregmatch(pattern: "Data Domain OS ([0-9.-]+)", string: uname);
if (!isnull(vers[1])) {
  version = vers[1];
  concluded = "    Version:  " + vers[0];
}

if (mod_info = ssh_cmd_exec(cmd: "system show modelno")) {
  # Model number: DD VE
  # Model number: DD990
  mod = eregmatch(pattern: "Model number\s*:\s*(.*)", string: mod_info);
  if (!isnull(mod[1])) {
    model = mod[1];
    if (concluded)
      concluded += '\n';

    concluded += "    Model:    " + mod[0];

    if ("DD VE" >< model)
      set_kb_item(name: "dell/powerprotect/data_domain/is_vm", value: TRUE);
  }
}

set_kb_item(name: "dell/powerprotect/data_domain/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "dell/powerprotect/data_domain/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "dell/powerprotect/data_domain/ssh-login/" + port + "/concluded", value: concluded);

exit(0);
