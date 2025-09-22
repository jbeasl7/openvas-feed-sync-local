# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105802");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-04-18T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"creation_date", value:"2016-07-07 16:59:41 +0200 (Thu, 07 Jul 2016)");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("IBM QRadar SIEM Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ibm/qradar/detected");

  script_tag(name:"summary", value:"SSH login-based detection of IBM QRadar SIEM.");

  exit(0);
}

include("host_details.inc");

if (!get_kb_item("ssh/login/ibm/qradar/detected"))
  exit(0);

port = get_kb_item("ssh/login/ibm/qradar/port");

version = "unknown";

set_kb_item(name: "ibm/qradar/siem/detected", value: TRUE);
set_kb_item(name: "ibm/qradar/siem/ssh-login/detected", value: TRUE);
set_kb_item(name: "ibm/qradar/siem/ssh-login/port", value: port);

# 7.3.1.20180720020816
# 7.3.3.20191031163225
if (vers = get_kb_item("ssh/login/ibm/qradar/" + port + "/version")) {
  version = vers;
  concluded = get_kb_item("ssh/login/ibm/qradar/" + port + "/conclfrom");
  if (concluded)
    set_kb_item(name: "ibm/qradar/siem/ssh-login/" + port + "/conclLoc", value: concluded);
}

set_kb_item(name: "ibm/qradar/siem/ssh-login/" + port + "/version", value: version);

exit(0);
