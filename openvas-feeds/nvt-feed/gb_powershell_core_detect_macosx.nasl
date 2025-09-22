# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812744");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-01-30 14:45:05 +0530 (Tue, 30 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("PowerShell Core Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  PowerShell on Mac OS X.

  The script logs in via ssh, searches for folder 'PowerShell.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

list = make_list("PowerShell-preview.app", "PowerShell.app");

foreach app (list)
{
  psVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" + app +
                                       "/Contents/Info CFBundleShortVersionString"));


  if(isnull(psVer)|| "does not exist" >< psVer){
    continue;
  }

  close(sock);

  ## For preview versions
  psVer = ereg_replace(pattern:"-preview", string:psVer, replace:"");

  set_kb_item(name: "PowerShell/MacOSX/Version", value:psVer);

  ## New cpe created
  cpe = build_cpe(value:psVer, exp:"^([0-9rc.-]+)", base:"cpe:/a:microsoft:powershell:");
  if(isnull(cpe))
    cpe = 'cpe:/a:microsoft:powershell';

  register_product(cpe:cpe, location:'/Applications/' + app);

  log_message(data: build_detection_report(app: "PowerShell",
                                           version: psVer,
                                           install: "/Applications/" + app,
                                           cpe: cpe,
                                           concluded: psVer));
}
exit(0);
