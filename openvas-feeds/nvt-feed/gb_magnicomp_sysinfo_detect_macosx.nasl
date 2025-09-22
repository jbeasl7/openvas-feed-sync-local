# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814051");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-10-04 12:30:19 +0530 (Thu, 04 Oct 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MagniComp SysInfo Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  MagniComp SysInfo Version on Mac OS X.

  The script logs in via ssh, searches for configuration file 'configvars.cfg'
  and queries the file for string 'ProdVersionFull'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  script_xref(name:"URL", value:"https://www.magnicomp.com");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/configvars\.cfg$", useregex:TRUE, sock:sock);
foreach binName (paths) {

  binName = chomp(binName);
  if(!binName)
    continue;

  magnicnf = ssh_get_bin_version(full_prog_name:"cat", sock:sock, version_argv:binName, ver_pattern:'IsMagniComp="yes');
  if(!magnicnf) break;

  sysinfoVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName, ver_pattern:'ProdVersionFull="([0-9A-Z. ]+)', sock:sock);
  if(sysinfoVer[1] != NULL)
  {
    sysinfoVer = sysinfoVer[1];
    set_kb_item(name:"MagniComp/SysInfo/Macosx/Ver", value:sysinfoVer);

    cpe = build_cpe(value:sysinfoVer, exp:"^([0-9A-Z.]+)", base:"cpe:/a:magnicomp:sysinfo:");
    if(!cpe)
      cpe = "cpe:/a:magnicomp:sysinfo";

    register_product(cpe:cpe, location:'/opt/sysinfo');

    log_message(data: build_detection_report(app:"MagniComp SysInfo",
                                             version:sysinfoVer,
                                             install:"/opt/sysinfo",
                                             cpe:cpe,
                                             concluded:sysinfoVer));
    exit(0);
  }
}
ssh_close_connection();
exit(0);
