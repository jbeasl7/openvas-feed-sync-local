# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800407");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NTPd Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the installed version of NTPd.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit( 0 );

binFiles = ssh_find_file(file_name:"/ntpd$", useregex:TRUE, sock:sock);
foreach binName(binFiles) {

  binName = chomp(binName);
  if(!binName)
    continue;

  ntpVer = ssh_get_bin_version(full_prog_name:binName, sock:sock, version_argv:"--version", ver_pattern:"ntpd.* ([0-9]\.[0-9.]+)([a-z][0-9]*)?-?((RC|beta)[0-9])?");
  if(!ntpVer[1])
    continue;

  version = "unknown";
  CPE = "cpe:/a:ntp:ntp";

  set_kb_item( name:"ntpd/ssh-login/detected", value:TRUE );
  set_kb_item( name:"ntpd/detected", value:TRUE );

  vers = eregmatch(string:ntpVer[0], pattern:"ntpd.* ([0-9]\.[0-9.]+)([a-z][0-9]*)?-?((RC|beta)[0-9])?");
  if(vers[2] =~ "[a-z][0-9]+" && vers[3] =~ "(RC|beta)") {
    version = vers[1] + vers[2] + " " + vers[3];
    CPE += ":" + vers[1] + ":" + vers[2] + "-" + vers[3];
  } else if(vers[2] =~ "[a-z][0-9]*") {
    version = vers[1] + vers[2];
    CPE += ":" + vers[1] + ":" + vers[2];
  } else {
    version = vers[1];
    CPE += ":" + vers[1];
  }

  if( version && version != "unknown" ) {

    CPE = tolower( CPE );
    set_kb_item( name:"ntpd/version/detected", value:TRUE );
    set_kb_item( name:"ntpd/version", value:version );
    set_kb_item( name:"ntpd/0/version", value:version );

    set_kb_item( name:"ntpd/ssh-login/version/detected", value:TRUE );
    set_kb_item( name:"ntpd/ssh-login/version", value:version );
    set_kb_item( name:"ntpd/ssh-login/0/version", value:version );
  }

  register_product( cpe:CPE, location:binName, port:0, service:"ssh-login" );

  log_message( data:build_detection_report( app:"NTPd",
                                            version:version,
                                            install:binName,
                                            cpe:CPE,
                                            concluded:ntpVer[0] ),
              port:0 );
}

ssh_close_connection();

exit( 0 );
