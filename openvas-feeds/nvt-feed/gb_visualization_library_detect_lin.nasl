# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800997");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-03-08T15:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-08 15:37:10 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Visualization Library Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Visualization Library.");

  exit(0);
}

include("ssh_func.inc");

if(!sock = ssh_login_or_reuse_connection())
  exit(0);

paths = ssh_find_file(file_name:"/version\.hpp$", useregex:TRUE, sock:sock);
if(!paths) {
  ssh_close_connection();
  exit(0);
}

foreach binName (paths) {

  binName = chomp(binName);
  if(!binName || binName !~ "/vl/")
    continue;

  rpVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName, ver_pattern:".+", sock:sock);
  if(!rpVer[1])
    continue;

  mjVer = eregmatch(pattern:"VL_Major ([0-9]+)", string:rpVer[1], icase:TRUE);
  mnVer = eregmatch(pattern:"VL_Minor ([0-9]+)", string:rpVer[1], icase:TRUE);
  blVer = eregmatch(pattern:"VL_Build ([0-9]+)", string:rpVer[1], icase:TRUE);

  if(!isnull(mnVer[1])) {
    vlVer = mjVer[1] + "." + mnVer[1] + "." + blVer[1];
    if(!isnull(vlVer)) {
      set_kb_item(name:"VisualizationLibrary/Linux/Ver", value:vlVer);
      log_message(data:"Visualization Library version " + vlVer + " was detected on the host");
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);
