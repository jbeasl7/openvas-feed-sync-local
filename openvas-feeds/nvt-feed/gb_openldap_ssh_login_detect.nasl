# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146147");
  script_version("2024-11-28T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-28 05:05:41 +0000 (Thu, 28 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-06-18 03:03:16 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("OpenLDAP Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenLDAP.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_file(file_name: "/slapd$", sock: soc, useregex: TRUE);

foreach file (paths) {

  file = chomp(file);
  if (!file)
    continue;

  version = "unknown";

  # @(#) $OpenLDAP: slapd 2.4.46 $
  # @(#) $OpenLDAP: slapd 2.4.44 (Apr 28 2021 13:32:00) $
  # @(#) $OpenLDAP: slapd  (Ubuntu) (Apr  8 2021 04:22:01) $
  # @(#) $OpenLDAP: slapd  (Feb 14 2021 18:32:34) $
  # @(#) $OpenLDAP: slapd 2.4.49 (Jun  2 2021 09:00:31) $
  # @(#) $OpenLDAP: slapd 2.4.57+dfsg-3+deb11u1 (May 14 2022 18:32:57) $
  # @(#) $OpenLDAP: slapd  (May 30 2017 07:55:01) $
  #
  # nb: It is important to use "-VV" here because if only using "-V" and e.g. a "root" user for
  # scanning (which is allowed to bind on the relevant ports) the binary seems to show a
  # non-standard behavior to startup instead of exiting.
  #
  # From e.g. a "slapd --test" call:
  #
  # -V print version info (-VV exit afterwards, -VVV print info about static overlays and backends)
  #
  # or from https://www.openldap.org/software/man.cgi?query=slapd:
  #
  # -V[V[V]] Print version info and proceed with startup. If -VV is given, exit after providing
  #          version info. If -VVV is given, additionally provide information on static overlays and
  #          backends.
  #
  res = ssh_cmd(socket: soc, cmd: file + " -VV");
  if ("OpenLDAP: slapd " >< res) {
    vers = eregmatch(pattern: "OpenLDAP: slapd ([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "openldap/detected", value: TRUE);
    set_kb_item(name: "openldap/ssh-login/detected", value: TRUE);
    set_kb_item(name: "openldap/ssh-login/" + port + "/installs", value: "0#---#" + file + "#---#" + version + "#---#" + res);
  }
}

exit(0);
