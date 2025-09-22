# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809762");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-12-15 16:42:44 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe DNG Converter Detection (Mac OS X SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe DNG Converter on Mac OS X.

  The script logs in via ssh, searches for folder 'Adobe DNG Converter.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion' via
  command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

adName = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Adobe\ DNG\ Converter.app/Contents/Info " + "CFBundleName"));

close(sock);

if("DNG Converter" >< adName)
{
  adobeVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                 "Adobe\ DNG\ Converter.app/Contents/Info " + "CFBundleVersion"));

  if(isnull(adobeVer) || "does not exist" >< adobeVer){
    exit(0);
  }

  adobeVer = ereg_replace(pattern:"f", string:adobeVer, replace: ".");

  set_kb_item(name: "Adobe/DNG/Converter/MACOSX/Version", value:adobeVer);

  cpe = build_cpe(value:adobeVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:dng_converter:");
  if(isnull(cpe))
    cpe = "cpe:/a:adobe:dng_converter";

  register_product(cpe:cpe, location:'/Applications/Adobe DNG Converter.app');

  log_message(data: build_detection_report(app: "Adobe DNG Converter",
                                           version: adobeVer,
                                           install: "/Applications/Adobe DNG Converter.app",
                                           cpe: cpe,
                                           concluded: adobeVer));
  exit(0);
}
