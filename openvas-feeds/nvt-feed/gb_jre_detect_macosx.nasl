# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802736");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-06 18:27:52 +0530 (Fri, 06 Apr 2012)");

  script_name("Java Runtime Environment (JRE) Detection (Mac OS X SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  script_tag(name:"summary", value:"Detects the installed version of Java.

The script logs in via ssh, and gets the version via command line option
'java -version'.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if (!get_kb_item("ssh/login/osx_name")) {
  close(sock);
  exit(0);
}

javaVer = chomp(ssh_cmd(socket:sock, cmd:"java -version"));

close(sock);

if(isnull(javaVer) || "command not found" >< javaVer)
  exit(0);

javaVer = eregmatch(pattern:'java version "([0-9.]+_?[0-9]+)', string:javaVer);
if(javaVer[1])
{
  cpe = build_cpe(value:javaVer[1], exp:"^([0-9.]+_?[0-9]+)", base:"cpe:/a:oracle:jre:");
  if(!cpe)
    cpe = "cpe:/a:oracle:jre";

  register_product(cpe:cpe, location:'/System/Library/Java/JavaVirtualMachines');

  set_kb_item(name: "JRE/MacOSX/Version", value:javaVer[1]);
  log_message(data:'Detected Java version: ' + javaVer[1] +
                   '\nLocation: /System/Library/Java/JavaVirtualMachines' +
                   '\nCPE: '+ cpe +
                   '\n\nConcluded from version identification result:\n' +
                   "Java " + javaVer[1]);
}
