# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813733");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-07-30 14:23:59 +0530 (Mon, 30 Jul 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Oracle JRockit JVM Detection (Linux/Unix SSH Login)");

  script_tag(name:"summary", value:"Detects the installed version of Oracle
  JRockit JVM.

  The script logs in via ssh, searches for 'ReleaseInformation.xml' file and
  queries the found file for Oracle JRockit and version information.");

  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-jrockit-2192437.html");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

jr_sock = ssh_login_or_reuse_connection();
if(!jr_sock) exit( 0 );

jrName = ssh_find_file(file_name:"/ReleaseInformation.xml", sock:jr_sock);
foreach fileName (jrName)
{

  fileName = chomp(fileName);
  if(!fileName)
    continue;

  catRes = ssh_cmd(socket:jr_sock, timeout:120, cmd:"cat " + fileName);

  if(catRes && "product_name>Oracle JRockit<" >< catRes)
  {
    rocVer = eregmatch(pattern:"<product_version>([0-9u]+) (R([0-9.]+))<", string:catRes);
    jrockitVer = rocVer[2];
    jrockitjreVer = rocVer[1];
    path = eregmatch(pattern:"(.*)/jre/lib/ReleaseInformation.xml", string:fileName);
    jrockitPath = path[1];

    if(jrockitVer)
    {
      set_kb_item(name:"JRockit/Lin/Installed", value:TRUE);
      set_kb_item(name:"JRockit/Lin/Ver", value:jrockitVer);
      set_kb_item(name:"JRockit/Jre/Lin/Ver", value:jrockitjreVer);

      register_and_report_cpe(app:"JRockit JVM", ver:jrockitVer, base:"cpe:/a:oracle:jrockit:",
                              expr:"^(R[0-9.]+)", insloc:jrockitPath);

      ssh_close_connection();
      exit(0);
    }
  }
}

exit(0);
