# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811062");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-06-02 15:14:25 +0530 (Fri, 02 Jun 2017)");
  script_name("IBM Tivoli Storage Manager Client Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  IBM Tivoli Storage Manager Client.

  The script logs in via ssh, searches for folder 'Tivoli Storage Manager.app'
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

ibmVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Tivoli\ Storage\ Manager/Tivoli\ Storage\ Manager.app/Contents/" +
             "Info CFBundleShortVersionString"));
if(!ibmVer || "does not exist" >< ibmVer)
{
  ibmVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "IBM\ Spectrum\ Protect/IBM\ Spectrum\ Protect.app/Contents/" +
             "Info CFBundleShortVersionString"));
}
close(sock);

if(isnull(ibmVer) || "does not exist" >< ibmVer){
  exit(0);
}

set_kb_item(name: "IBM/TSM/Client/MacOSX", value:ibmVer);

cpe = build_cpe(value:ibmVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_storage_manager:");
if(isnull(cpe))
  cpe = "cpe:/a:ibm:tivoli_storage_manager";

ibmPath = "/Applications/Tivoli Storage Manager/Tivoli Storage Manager.app";
register_product(cpe:cpe, location:ibmPath);

log_message(data: build_detection_report(app: "IBM Tivoli Storage Manager",
                                         version:ibmVer,
                                         install:ibmPath,
                                         cpe:cpe,
                                         concluded: ibmVer));
exit(0);
