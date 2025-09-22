# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108494");
  script_version("2023-09-22T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-22 05:05:30 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-12-04 13:25:20 +0100 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (CODESYS)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_codesys_tcp_detect.nasl");
  script_mandatory_keys("codesys/tcp/detected");

  script_tag(name:"summary", value:"CODESYS programming interface / runtime based Operating System
  (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (CODESYS)";
BANNER_TYPE = "CODESYS Service information";

port = service_get_port( default:2455, proto:"codesys" );

# Only existing for Version 2 services
os_name = get_kb_item( "codesys/" + port + "/os_name" );
os_details = get_kb_item( "codesys/" + port + "/os_details" );

# Only existing for Version 3 services
target_name = get_kb_item( "codesys/" + port + "/targetName" );

if( os_name && os_details ) {

  report_banner  = '\nOS Name:    ' + os_name;
  report_banner += '\nOS Details: ' + os_details;

  if( os_name == "Windows" ) {

    # CE 5.0
    # CE.net (4.20) [runtime port v2
    # unknown CE version [runtime por
    # CE.net (4.x)

    ce_ver = eregmatch( pattern:"^CE ([0-9.]+)", string:os_details );
    if( ! isnull( ce_ver[1] ) ) {
      os_register_and_report( os:"Microsoft Windows CE", version:ce_ver[1], cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }

    ce_ver = eregmatch( pattern:"^CE\.net \(([0-9.x]+)", string:os_details );
    if( ! isnull( ce_ver[1] ) ) {
      os_register_and_report( os:"Microsoft Windows CE.net", version:ce_ver[1], cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }

    if( "unknown CE version" >< os_details ) {
      os_register_and_report( os:"Microsoft Windows CE", cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }

    if( "NT/2000/XP" >< os_details ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }

    os_register_unknown_banner( banner:report_banner, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );

  } else if( os_name == "Linux" ) {

    # os_name: Linux
    # os_detail: 3.18.13-rt10-w02.00.03+3 [runti
    # os_detail: 4.9.47-rt37-w02.02.00_01+10 [ru
    # os_detail: 2.6.29.6-rt24atom
    # os_name: RTLinux
    # os_detail: 2.4.31-adeos
    version = eregmatch( pattern:"^([0-9.]+)", string:os_details );
    if( ! isnull( version[1] ) ) {
      os_register_and_report( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }

  } else if( os_name == "Nucleus PLUS" ) {

    # os_name: Nucleus PLUS
    # os_detail: Nucleus PLUS version unknown
    os_register_and_report( os:"Nucleus RTOS", cpe:"cpe:/o:mentor:nucleus_rtos", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

    if( "Nucleus PLUS version unknown" >< os_details )
      exit( 0 );

    # Haven't seen any other then Nucleus PLUS version unknown "live" so reporting an unknown OS for all others and exit previously
    os_register_unknown_banner( banner:report_banner, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );

  } else if( os_name == "VxWorks" ) {

    # os_name: VxWorks
    # os_detail: 5.5.1 [runtime port v0 (2.4.7.0
    version = eregmatch( pattern:"^([0-9.]+)", string:os_details );
    if( ! isnull( version[1] ) ) {
      os_register_and_report( os:"Wind River VxWorks", version:version[1], cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }

  } else if( os_name == "@CHIP-RTOS" ) {

    # os_name: @CHIP-RTOS
    # os_detail: SC123/SC143 V2.03 FULL
    # os_detail: SC23/SC24 V1.81 Beta Test versi
    version = eregmatch( pattern:"^[^ ]+ V([0-9.]+)", string:os_details );
    if( ! isnull( version[1] ) ) {
      os_register_and_report( os:"@CHIP-RTOS", version:version[1], cpe:"cpe:/o:beck-ipc:chip-rtos", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      os_register_and_report( os:"@CHIP-RTOS", cpe:"cpe:/o:beck-ipc:chip-rtos", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }

  } else {
    os_register_unknown_banner( banner:report_banner, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );
  }

  # nb: No need to continue here as we either have a Version 2 (with os_name and os_details defined) or a
  # or a Version 3 (having target_name defined) service.
  exit( 0 );
}

if( ! target_name )
  exit( 0 );

# CODESYS Control for Linux SL
if( "for Linux" >< target_name ) {
  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# CODESYS Control for Raspberry Pi MC SL
# CODESYS Control for Raspberry Pi SL
#
# nb: On a Raspberry Pi various OS variants like Debian, FreeBSD and similar is possible.
if( "for Raspberry Pi" >< target_name ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Currently unknown OS:
#
# CODESYS Control for BeagleboneBlack SL
# CODESYS Control for PFC100 SL
# CODESYS Control for PFC200 SL

os_register_unknown_banner( banner:target_name, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );

exit( 0 );
