# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117229");
  script_version("2025-02-06T05:38:57+0000");
  script_tag(name:"last_modification", value:"2025-02-06 05:38:57 +0000 (Thu, 06 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-02-17 11:51:47 +0000 (Wed, 17 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Tomcat Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Apache Tomcat.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

# nb: Manual installations from the Tomcat tarballs have "/<install-path>/bin/catalina.sh" but
# package based installations (at least on CentOS 7) have just "tomcat".
# nb: Ubuntu 20.04 package based installations have /usr/share/tomcat9/bin/catalina.sh again.
full_path_list = ssh_find_file( file_name:"/(tomcat|catalina\.sh)$", sock:sock, useregex:TRUE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

port = kb_ssh_transport();

foreach full_path( full_path_list ) {

  full_path = chomp( full_path );
  if( ! full_path )
    continue;

  # For both mentiones files above:
  # Server version: Apache Tomcat/10.0.2
  # Server version: Apache Tomcat/9.0.43
  # Server version: Apache Tomcat/9.0.31 (Ubuntu)
  # Server version: Apache Tomcat/8.5.63
  # Server version: Apache Tomcat/7.0.76

  vers = ssh_get_bin_version( full_prog_name:full_path, sock:sock, version_argv:"version", ver_pattern:"(Server version\s*:\s*Apache Tomcat/([0-9.-]+)|Neither the JAVA_HOME nor the JRE_HOME environment variable is defined\s+At least one of these environment variable is needed to run this program)" );
  if( ! vers || ! vers[2] )
    continue;
  concluded = "";
  if( "Neither the JAVA_HOME nor the JRE_HOME" >< vers[1] ) {
    version = "unknown";
    version_found = FALSE;
    if ( full_path =~ "bin/(tomcat|catalina\.sh)$" ) {
      jar_path = ereg_replace( string:full_path, pattern:"bin/(tomcat|catalina\.sh)$", replace:"lib/catalina.jar" );

      ssh_cmd_file_cont = "unzip -p " + jar_path + " org/apache/catalina/util/ServerInfo.properties";

      serverinfo_content = ssh_cmd( socket:sock, cmd:ssh_cmd_file_cont, timeout:60, return_errors:TRUE, return_linux_errors_only:TRUE );

      if( "No such file or directory" >< serverinfo_content ||
           "not found" >< serverinfo_content ) {
        #nb: we retry with jar command
        ssh_cmd_file_cont = "jar xf " + jar_path + " org/apache/catalina/util/ServerInfo.properties";
        serverinfo_content = ssh_cmd( socket:sock, cmd:ssh_cmd_file_cont, timeout:60, return_errors:TRUE, return_linux_errors_only:TRUE );
      }
      # server.info=Apache Tomcat/9.0.83
      vers = eregmatch( string:serverinfo_content, pattern:"server\.info\s*=\s*Apache Tomcat/([0-9.-]+)", icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        concluded = vers[0];
        version_found = TRUE;
        full_path = jar_path;
      }
    }
    if( ! version_found ) {
      concluded = vers[1];
      extra   = "The scanning user is misconfigured and doesn't have a 'JAVA_HOME' or 'JRE_HOME' defined (Java might be not installed). ";
      extra  += "Version detection of Apache Tomcat is not possible. Please correct the setup according to the Operating System or Apache Tomcat manual.";
    }
  } else {
    version = vers[2];
    concluded = vers[1];
  }

  set_kb_item( name:"apache/tomcat/detected", value:TRUE );
  set_kb_item( name:"apache/tomcat/ssh-login/detected", value:TRUE );
  # nb: "#---##---#" is expected below as we don't have a "Concluded URL" like defined by the HTTP Detection-VT.
  set_kb_item( name:"apache/tomcat/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---##---#" + extra );
}

ssh_close_connection();
exit( 0 );
