# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105304");
  script_version("2024-05-01T05:05:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-01 05:05:35 +0000 (Wed, 01 May 2024)");
  script_tag(name:"creation_date", value:"2015-06-24 13:13:10 +0200 (Wed, 24 Jun 2015)");
  script_name("F5 LineRate / LROS Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("f5/LROS/show_version");

  script_tag(name:"summary", value:"SSH login-based detection of F5 LineRate and the underlying
  LineRate Operating System (LROS).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");

infos = get_kb_item( "f5/LROS/show_version" );

if( ! infos || "F5 Networks LROS" >!< infos )
  exit( 0 );

app_cpe = "cpe:/a:f5:linerate";
os_cpe  = "cpe:/o:f5:lros";
version = "unknown";
install = "/";

set_kb_item( name:"f5/linerate/detected", value:TRUE );
set_kb_item( name:"f5/linerate/ssh-login/detected", value:TRUE );

vers = eregmatch( pattern:'F5 Networks LROS Version ([0-9.]+[^\r\n ]+)', string:infos );
if( ! isnull( vers[1] ) ) {
  version = vers[1];

  os_cpe += ":" + version;

  # nb: NVD currently only knows the cpe:/a: CPE and uses the OS version within it so we're doing
  # the same here in addition to saving the version in the os_cpe. It's unlikely that this will ever
  # change as the product is already EOL.
  app_cpe += ":" + version;
}

register_product( cpe:app_cpe, location:install, port:0, service:"ssh-login" );
register_product( cpe:os_cpe, location:install, port:0, service:"ssh-login" );

os_register_and_report( os:"F5 LineRate Operating System (LROS)", cpe:os_cpe, port:0,
                        full_cpe:TRUE, banner:infos,
                        banner_type:"'show version' command", runs_key:"unixoide",
                        desc:"F5 LineRate / LROS Detection (SSH Login)" );

# nb: Seems to be based on FreeBSD according to https://my.f5.com/manage/s/article/K16495 so this
# is getting registered here as well.
os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", port:0,
                        full_cpe:TRUE, banner:infos,
                        banner_type:"'show version' command", runs_key:"unixoide",
                        desc:"F5 LineRate / LROS Detection (SSH Login)" );

log_message( data:build_detection_report( app:"F5 LineRate",
                                          version:version,
                                          install:install,
                                          concluded:infos,
                                          cpe:app_cpe ),
             port:0 );
exit( 0 );
