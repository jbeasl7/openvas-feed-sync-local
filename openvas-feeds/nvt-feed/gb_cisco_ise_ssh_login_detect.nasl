# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105469");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2015-12-01 13:44:48 +0100 (Tue, 01 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco Identity Services Engine (ISE) Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/cisco/ise/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco Identity Services Engine
  (ISE).");

  exit(0);
}

if (!port = get_kb_item("ssh/login/cisco/ise/port"))
  exit(0);

if (!show_version = get_kb_item("ssh/login/cisco/ise/" + port + "/show_ver"))
  exit(0);

version = "unknown";
patch = "0";

set_kb_item(name: "cisco/ise/detected", value: TRUE);
set_kb_item(name: "cisco/ise/ssh-login/detected", value: TRUE);
set_kb_item(name: "cisco/ise/ssh-login/port", value: port);
set_kb_item(name: "cisco/ise/ssh-login/" + port + "/concluded", value: chomp(show_version));

# nb: Needs to be done as the 'show version' includes as well the OS version
sv = split(show_version, keep: FALSE);
x = 0;

foreach line (sv) {
  x++;
  if ("Cisco Identity Services Engine" >< line && "Patch" >!< line && sv[x] =~ "^--------") {
    vers = eregmatch(pattern: '[^ ]*Version\\s*:\\s*([0-9]+[^\r\n]+)', string: sv[x + 1]); # e.g.: 1.1.4.218
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if ("Cisco Identity Services Engine Patch" >< line && sv[x] =~ "^--------") {
    p_version = eregmatch(pattern: '[^ ]*Version\\s*:\\s*([0-9]+)', string: sv[x + 1]); # e.g.: 13
    if (!isnull(p_version[1]))
      patch = p_version[1];
  }
}

set_kb_item(name: "cisco/ise/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "cisco/ise/ssh-login/" + port + "/patch", value: patch);

exit(0);
