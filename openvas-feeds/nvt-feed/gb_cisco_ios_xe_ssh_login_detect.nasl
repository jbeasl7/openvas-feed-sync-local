# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105658");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-05-09 15:41:31 +0200 (Mon, 09 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco IOS XE Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco IOS XE.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");

  exit(0);
}

include("ssh_func.inc");

if (!show_ver = get_kb_item("cisco/show_version"))
  exit(0);

if (show_ver !~ 'IOS[ -]XE Software.*,')
  exit(0);

port = get_kb_item("cisco/ssh-login/port");

concluded = show_ver;
version = "unknown";
model = "unknown";
image = "unknown";

set_kb_item(name: "cisco/ios_xe/detected", value: TRUE);
set_kb_item(name: "cisco/ios_xe/ssh-login/port", value: port);

sv = split(show_ver, keep: FALSE);

foreach line (sv) {
  if (line =~ "^.*IOS[ -](XE)?.*Version( Denali)? [0-9.]+") {
    vers = eregmatch(pattern: "Version( Denali)? ([^ ,\r\n]+)", string: line);
    break;
  }
}

if (!isnull(vers[2]))
  version = vers[2];

if (show_ver =~ "Cisco IOS Software, ASR[0-9]+") {
  mod = eregmatch(pattern: "Cisco IOS Software, (ASR[0-9]+)", string: show_ver);
  if (!isnull(mod[1]))
    model = mod[1];
} else {
  mod = eregmatch(pattern: "cisco ([^\(]+) \([^\)]+\) processor", string: show_ver);
  if (isnull(mod[1])) {
    if (soc = ssh_login_or_reuse_connection()) {
      buf = ssh_cmd(socket: soc, cmd: "show inventory", nosh: TRUE);
      # Currently looking only for Catalyst as e.g. modules/slots might introduce wrong model detection
      # PID: C9300-48P , VID: V02 , SN: FOC2333X0JZ
      mod = eregmatch(pattern: "PID: (C[^, ]+)", string: buf);
      if (mod)
        concluded += '\n' + buf;
      ssh_close_connection(socket: soc);
    }
  }

  if (!isnull(mod[1]))
    model = mod[1];
}

img = eregmatch(pattern: "\(([^)]+)\), *Version", string: show_ver);
if (!isnull(img[1]))
  image = img[1];

set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/concluded", value: concluded);
set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "cisco/ios_xe/ssh-login/" + port + "/image", value: image);

exit(0);
