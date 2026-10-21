# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105144");
  script_version("2026-10-20T05:48:09+0000");
  script_tag(name:"last_modification", value:"2026-10-20 05:48:09 +0000 (Tue, 20 Oct 2026)");
  script_tag(name:"creation_date", value:"2014-12-18 17:03:13 +0100 (Thu, 18 Dec 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Citrix XenServer Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/citrix/xenserver/detected");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Citrix XenServer.");

  exit(0);
}

include("ssh_func.inc");

if (!port = get_kb_item("ssh/citrix/xenserver/port"))
  exit(0);

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

file = "/etc/xensource-inventory";

inventory = ssh_cmd(socket: soc, cmd: "cat " + file);
if ("BUILD_NUMBER" >!< inventory || "PRODUCT_VERSION" >!< inventory)
  exit(0);

patch_list = ssh_cmd(socket: soc, cmd: "xe patch-list params=name-label,hosts");

close(soc);

version = "unknown";
build = "unknown";

set_kb_item(name: "citrix/xenserver/detected", value: TRUE);
set_kb_item(name: "citrix/xenserver/ssh-login/detected", value: TRUE);
set_kb_item(name: "citrix/xenserver/ssh-login/port", value: port);
set_kb_item(name: "citrix/xenserver/ssh-login/" + port + "/concluded", value: inventory);
set_kb_item(name: "citrix/xenserver/ssh-login/" + port + "/concludedFile", value: "/etc/xensource-inventory");

vers = eregmatch(pattern: "PRODUCT_VERSION\s*=\s*'([^']+)'", string: inventory);
if (!isnull(vers[1] ) )
  version = vers[1];

# nb: New "stream" doesn't have a build number
if (inventory !~ "BUILD_NUMBER\s*=\s*'stream'") {
  bld = eregmatch(pattern: "BUILD_NUMBER\s*=\s*'([^0-9]+)?([^']+)'", string: inventory);
  if (!isnull(bld[2]))
    build = bld[2];
}

if ("name-label" >< patch_list) {
  lines = split(patch_list, keep: FALSE);

  for (x = 0; x < max_index(lines); x++) {
    if (lines[x] =~ "name-label") {
      # Hotfix was uploaded but not installed. Handle it like a missing hotfix.
      if (lines[x + 1] =~ 'hosts.*: $') {
        continue;
      }
      patches += lines[x] + '\n';
    }
  }
}

set_kb_item(name: "citrix/xenserver/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "citrix/xenserver/ssh-login/" + port + "/build", value: build);
if (patches)
  set_kb_item(name: "citrix/xenserver/ssh-login/" + port + "/patches", value: patches);

exit(0);
