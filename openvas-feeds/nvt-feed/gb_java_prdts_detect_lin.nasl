# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800385");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Multiple Java Products Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Java products
  on Linux systems. It covers the following:

  - Sun Java

  - Oracle Java

  - IBM Java

  - GCJ

  The script logs in via ssh, searches for executables 'javaaws' and
  'java' and queries the found executables via command line option '-fullversion'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

jwspaths = ssh_find_bin( prog_name:"javaws", sock:sock );
if( jwspaths ) {
  foreach executableFile( jwspaths ) {

    executableFile = chomp(executableFile);
    if(!executableFile)
      continue;

    jwsVer = ssh_get_bin_version( full_prog_name:executableFile, sock:sock, version_argv:"-fullversion", ver_pattern:"Java\(TM\) Web Start ([0-9_.]+)" );
    if( ! isnull( jwsVer[1] ) ) {
      set_kb_item( name:"Java/WebStart/Linux/Ver", value:jwsVer[1] );
      register_and_report_cpe( app:"Java WebStart", ver:jwsVer[1], concluded:jwsVer[0], base:"cpe:/a:sun:java_web_start:", expr:"^([0-9]\.[0-9_.]+)", insloc:executableFile );
    }
  }
}

javapaths = ssh_find_bin( prog_name:"java", sock:sock );
if( javapaths ) {
  foreach executableFile( javapaths ) {

    executableFile = chomp(executableFile);
    if(!executableFile)
      continue;

    javaVer = ssh_get_bin_version( full_prog_name:executableFile, sock:sock, version_argv:"-fullversion ", ver_pattern:'java.? full version (.*)' );
    # LibGCJ
    if( "gcj" >< javaVer[1] ) {
      gcjVer = eregmatch( pattern:"([0-9]\.[0-9_.]+)", string:javaVer[2] ); # TODO: This doesn't match the regex in get_bin_version above...
      if( ! isnull( gcjVer[1] ) ) {
        set_kb_item( name:"Java/JRE/Linux/LibGCJ/Ver", value:gcjVer[1] );
        log_message( data:'Detected Java LibGCJ version: ' + gcjVer[1] + '\nLocation: ' + executableFile + '\n\nConcluded from version identification result:\n' + javaVer[max_index(javaVer)-1] );
      }
    }
    # IBM Java
    else if( "IBM" >< javaVer[1] )
    {
      ibmjreVer = eregmatch( pattern:"([0-9]\.[0-9._]+).*(SR[0-9]+)", string:javaVer[1] );
      if( ibmjreVer[1] && ! isnull( ibmjreVer[2]))
      {
        ibmjreVer = ibmjreVer[1] + "." + ibmjreVer[2];
        set_kb_item( name:"IBM/Java/JRE/Linux/Ver", value:ibmjreVer );
        log_message( data:'Detected IBM Java JRE version: ' + ibmjreVer + '\nLocation: ' + executableFile + '\n\nConcluded from version identification result:\n' + javaVer[max_index(javaVer)-1]);
      }
      ibmsdkVer = eregmatch( pattern:"IBM Linux build ([0-9.]+)", string:javaVer[1] );
      if(ibmsdkVer[1])
      {
        set_kb_item( name:"IBM/Java/SDK/Linux/Ver", value:ibmsdkVer[1] );
        cpe = build_cpe( value:ibmsdkVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ibm:java_sdk:" );
        if( isnull( cpe ) )
          cpe = "cpe:/a:ibm:java_sdk";

        register_and_report_cpe( app:"IBM Java SDK", ver:ibmsdkVer[1], concluded:ibmsdkVer[0], cpename:cpe, insloc:executableFile );
      }
    }
    # Sun/Oracle Java
    else if( javaVer[1] =~ "([0-9]\.[0-9._]+)-([b0-9]+)" || javaVer[1] =~ "([0-9.]+\+)")
    {
      jvVer    = ereg_replace( pattern:"_|-", string:javaVer[1], replace:"." );
      javaVer1 = eregmatch( pattern:"([0-9]+\.[0-9]+\.[0-9]+)(\.([0-9]+))?", string:jvVer );
      if( javaVer1[1] && javaVer1[3] ) {
        javaVer_or = javaVer1[1] + ":update_" + javaVer1[3];
      } else if( javaVer1[1] ) {
        javaVer_or = javaVer1[1];
      }
      else
      {
        jvVer = eregmatch( pattern:"([0-9.]+)", string:javaVer[1] );
        jvVer = jvVer[1];
        javaVer_or = jvVer;
      }

      if(version_is_less( version:jvVer, test_version:"1.4.2.38" )||
         version_in_range( version:jvVer, test_version:"1.5", test_version2:"1.5.0.33" )||
         version_in_range( version:jvVer, test_version:"1.6", test_version2:"1.6.0.18" ) )
      {
        java_name = "Sun Java";
        if(("jdk" >< executableFile && "jre" >!< executableFile) || ("jdk"  ><  executableFile && "jre" >< executableFile))
        {
          cpe = build_cpe( value:javaVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jdk:" );
          if( isnull( cpe ) )
            cpe = "cpe:/a:sun:jdk";
          set_kb_item( name:"Sun/Java/JDK/Linux/detected", value:TRUE );
          set_kb_item( name:"Sun/Java/JDK_or_JRE/Linux/detected", value:TRUE );
        }
        else
        {
          cpe = build_cpe( value:javaVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jre:" );
          if( isnull( cpe ) )
            cpe = "cpe:/a:sun:jre";
          set_kb_item( name:"Sun/Java/JRE/Linux/detected", value:TRUE );
          set_kb_item( name:"Sun/Java/JDK_or_JRE/Linux/detected", value:TRUE );
          set_kb_item( name:"Sun_or_Oracle/Java/JRE/Linux/detected", value:TRUE );
        }
      }
      else
      {
        java_name = "Oracle Java";
        if(("jdk" >< executableFile && "jre" >!< executableFile) || ("jdk"  ><  executableFile && "jre" >< executableFile))
        {
          cpe = build_cpe( value:javaVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jdk:" );
          if( isnull( cpe ) )
            cpe = "cpe:/a:oracle:jdk";
          set_kb_item( name:"Oracle/Java/JDK/Linux/detected", value:TRUE );
          set_kb_item( name:"Oracle/Java/JDK_or_JRE/Linux/detected", value:TRUE );
        }
        else
        {
          cpe = build_cpe( value:javaVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jre:" );
          if( isnull( cpe ) )
            cpe = "cpe:/a:oracle:jre";
          set_kb_item( name:"Oracle/Java/JRE/Linux/detected", value:TRUE );
          set_kb_item( name:"Oracle/Java/JDK_or_JRE/Linux/detected", value:TRUE );
          set_kb_item( name:"Sun_or_Oracle/Java/JRE/Linux/detected", value:TRUE );
        }
      }

      set_kb_item( name:"Sun/Java/JRE/Linux/Ver", value:javaVer[1] );
      set_kb_item( name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE );
      set_kb_item( name:"Sun_or_Oracle/Java/JDK_or_JRE/Linux/detected", value:TRUE );
      register_and_report_cpe( app:java_name, ver:javaVer[1], concluded:javaVer_or, cpename:cpe, insloc:executableFile );
    }
  }
}

ssh_close_connection();
