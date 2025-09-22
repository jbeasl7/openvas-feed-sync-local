# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140226");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-03-30 13:47:37 +0200 (Thu, 30 Mar 2017)");
  script_name("GitHub Enterprise Detection (Linux/Unix SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of GitHub Enterprise.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("github/enterprise/rls");

  exit(0);
}

include("host_details.inc");

if( ! rls = get_kb_item( "github/enterprise/rls" ) )
  exit( 0 );

set_kb_item( name:"github/enterprise/detected", value:TRUE );
set_kb_item( name:"github/enterprise/ssh-login/detected", value:TRUE );

version = "unknown";
install = "/";
cpe = "cpe:/a:github:github_enterprise";
conclCmd = "cat /etc/github/enterprise-release";

# RELEASE_VERSION="2.8.6"
# RELEASE_PLATFORM="esx"
# RELEASE_BUILD_ID="5bfb10e"
# RELEASE_BUILD_DATE="2017-01-12T03:54:56Z"
vers = eregmatch( pattern:'RELEASE_VERSION="([^"]+)"', string:rls );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  cpe += ":" + version;
  set_kb_item( name:"github/enterprise/version", value:version );
}

bld = eregmatch( pattern:'RELEASE_BUILD_ID="([^"]+)"', string:rls );
if( ! isnull( bld[1] ) ) {
  set_kb_item( name:"github/enterprise/build", value:bld[1] );
  extra = "  Build ID: " + bld[1];
}

pltfrm = eregmatch( pattern:'RELEASE_PLATFORM="([^"]+)"', string:rls );
if( ! isnull( pltfrm[1] ) ) {
  set_kb_item( name:"github/enterprise/release_platform", value:pltfrm[1] );
  if( extra )
    extra += '\n';
  extra += "  Release platform: " + pltfrm[1];
}

register_product( cpe:cpe, location:install, port:0, service:"ssh-login" );

report = build_detection_report( app:"GitHub Enterprise",
                                 version:version,
                                 install:install,
                                 cpe:cpe,
                                 concluded:vers[0],
                                 concludedUrl:conclCmd,
                                 extra:extra );

log_message( port:0, data:report );

exit( 0 );
