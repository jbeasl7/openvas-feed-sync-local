# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800335");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("OpenSSL Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenSSL.");

  script_tag(name:"vuldetect", value:"Note: This routine detects OpenSSL based on the availability
  of the 'openssl' command line tool.");

  exit(0);
}

include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

port = kb_ssh_transport();

full_path_list = ssh_find_file(file_name: "/openssl$", sock: soc, useregex: TRUE);
if (!full_path_list) {
  ssh_close_connection();
  exit(0);
}

found = FALSE;

foreach full_path (full_path_list) {
  if (!full_path = chomp(full_path))
    continue;

  # OpenSSL 1.1.1f  31 Mar 2020
  #
  cmd = full_path + " version";
  vers = ssh_get_bin_version(full_prog_name: full_path, sock: soc, version_argv: "version",
                             ver_pattern: "OpenSSL ([0-9.a-z]+)");
  if (!isnull(vers[1])) {
    found = TRUE;
    set_kb_item(name: "openssl/ssh-login/" + port + "/installs",
                value: "0#---#" + full_path + "#---#" + vers[1] + "#---#" + vers[0] + "#---#Used command: " + cmd);
  }
}

# nb: We only need to set the generic KB keys once so this was placed outside of the loop above.
if (found) {
  set_kb_item(name: "openssl/detected", value: TRUE);
  set_kb_item(name: "openssl_or_gnutls/detected", value: TRUE);
  set_kb_item(name: "openssl/ssh-login/detected", value: TRUE);
}

ssh_close_connection();

exit(0);
