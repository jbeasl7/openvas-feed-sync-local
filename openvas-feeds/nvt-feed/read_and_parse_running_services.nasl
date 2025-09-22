# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150264");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-06-09 13:08:41 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Get running services");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.tecmint.com/list-all-running-services-under-systemd-in-linux/");

  script_tag(name:"summary", value:"A service is a process or group of processes (commonly known as
daemons) running continuously in the background, waiting for requests to come in (especially from
clients).

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/systemctl/running/ssh/ERROR", value:TRUE);
  exit(0);
}

cmd = "systemctl --no-pager --state=running --no-legend";
ret = ssh_cmd_without_errors(socket:sock, cmd:cmd);
if(!ret){
  set_kb_item(name:"Policy/linux/systemctl/running/ERROR", value:TRUE);
  exit(0);
}

foreach row (split(ret, keep:FALSE)){
  match = split(row, sep:" ", keep:FALSE);
  if(match){
    set_kb_item(name:"Policy/linux/systemctl/running", value:match[0]);
  }
}

exit(0);