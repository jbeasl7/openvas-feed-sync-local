# SPDX-FileCopyrightText: 2005 SecuriTeam
# SPDX-FileCopyrightText: Reworked, improved and extended detection code and pattern since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10281");
  script_version("2025-06-16T05:41:07+0000");
  script_tag(name:"last_modification", value:"2025-06-16 05:41:07 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Telnet Banner Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("telnet.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:"This scripts reports the received banner of a Telnet service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("dump.inc");
include("telnet_func.inc");
include("misc_func.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if( strlen( banner ) ) {

  if( "login:" >!< tolower( banner ) ) {
    # nb: For check_account() of default_account.inc
    set_kb_item( name:"telnet/" + port + "/no_login_banner", value:TRUE );
    set_kb_item( name:"telnet/no_login_banner", value:TRUE );
  } else {
    # nb: For VTs which should run against all telnet services having a "login:" banner
    set_kb_item( name:"telnet/" + port + "/login_banner/available", value:TRUE );
    set_kb_item( name:"telnet/login_banner/available", value:TRUE );
  }

  set_kb_item( name:"telnet/banner/available", value:TRUE );
  set_kb_item( name:"ssh_or_telnet/banner/available", value:TRUE );

  # nb: Safeguard if telnet.nasl failed on fragile ports
  if( service_is_unknown( port:port ) )
    service_register( port:port, proto:"telnet", message:"A Telnet server seems to be running on this port" );

  # nb:
  # - Keep the pattern in sync with the one in sw_telnet_os_detection.nasl
  # - At least older Cisco IOS and Cisco IOS XE versions shared the same login prompt
  if( "User Access Verification" >< banner && ( "Username:" >< banner || banner =~ "Cisco" || "Password:" >< banner || "IOS" >< banner ) ) {
    set_kb_item( name:"telnet/cisco/ios/detected", value:TRUE );
    set_kb_item( name:"telnet/cisco/ios_xe/detected", value:TRUE );
    guess += '\n- Cisco IOS / Cisco IOS XE';
  }

  if( "Welcome to ZXDSL 831CII" >< banner ) {
    set_kb_item( name:"telnet/zte/zxdsl_831cii/detected", value:TRUE );
    guess += '\n- ZTE ZXDSL 831CII';
  }

  if( "MikroTik" >< banner && "Login:" >< banner ) {
    set_kb_item( name:"telnet/mikrotik/routeros/detected", value:TRUE );
    guess += '\n- MikroTik RouterOS';
  }

  if( "Huawei TE" >< banner ) {
    set_kb_item( name:"telnet/huawei/te/detected", value:TRUE );
    guess += '\n- Huawei TE Device';
  }

  if( "HP JetDirect" >< banner ) {
    set_kb_item( name:"telnet/hp/jetdirect/detected", value:TRUE );
    guess += '\n- HP JetDirect Device';
  }

  if( "IQinVision " >< banner ) {
    set_kb_item( name:"telnet/vicon_industries/network_camera/detected", value:TRUE );
    guess += '\n- Vicon Industries Network Camera';
  }

  if( "Broadband Satellite" >< banner && "Hughes Network Systems" >< banner ) {
    set_kb_item( name:"telnet/hughes_network_systems/broadband_satellite_modem/detected", value:TRUE );
    guess += '\n- Hughes Broadband Satellite Modem';
  }

  if( "VxWorks login:" >< banner ) {
    set_kb_item( name:"telnet/vxworks/detected", value:TRUE );
    guess += '\n- VxWorks Embedded Device';
    fragile =  '\n\nNote: Some specific variants of this service (e.g. running on Kronos 4500) are known to be "fragile" or slow to ';
    fragile += 'respond. If you don\'t get any results for this service please consider to:';
    fragile += '\n- raise the "time_between_request" scanner preference';
    fragile += '\n- add "Services/telnet, ' + port + '" to the "non_simult_ports" scanner preference';
  }

  if( "Welcome to NetLinx" >< banner ) {
    set_kb_item( name:"telnet/netlinx/detected", value:TRUE);
    guess += '\n- NetLinx Controller';
  }

  if( banner =~ "Model name\s*:\s*MiiNePort " ) {
    set_kb_item( name:"telnet/moxa/miineport/detected", value:TRUE );
    guess += '\n- Moxa MiiNePort';
  }

  if( banner =~ "Model name\s*:\s*MGate " ) {
    set_kb_item( name:"telnet/moxa/mgate/detected", value:TRUE );
    guess += '\n- Moxa MGate';
  }

  if( ( "Please keyin your password" >< banner || "Please keyin your username" >< banner ) &&
      banner !~ "MiiNePort" && banner !~ "MGate" &&
      eregmatch( pattern:'Model name\\s*:\\s(NPort )?([^ \r\n]+)', string:banner ) ) {
    set_kb_item( name:"telnet/moxa/nport/detected", value:TRUE );
    guess += '\n- Moxa NPort';
  }

  if( banner =~ "OnCell G[0-9]{4}" ) {
    set_kb_item( name:"telnet/moxa/oncell/detected", value:TRUE );
    guess += '\n- Moxa OnCell';
  }

  if( "Welcome to V" >< banner && ( "VibNode" >< banner || "VIBNODE" >< banner ) ) {
    set_kb_item( name:"telnet/pruftechnik/vibnode/detected", value:TRUE );
    guess += '\n- PRUFTECHNIK VIBNODE';
  }

  if( "WAC" >< banner && "Foxit Software" >< banner ) {
    set_kb_item( name:"telnet/foxit/wac-server/detected", value:TRUE );
    set_kb_item( name:"ssh_or_telnet/foxit/wac-server/detected", value:TRUE );
    guess += '\n- Foxit Software WAC Server';
  }

  if( "Model: ZNID-GPON" >< banner ) {
    set_kb_item( name:"telnet/zhone/znid_gpon/detected", value:TRUE );
    guess += '\n- ZHONE ZNID GPON Device';
  }

  # nb: See the comment about the device name in gb_netgear_prosafe_telnet_detect.nasl
  if( "User:" >< banner && ( "(GSM7224V2)" >< banner || "(GSM7224)" >< banner ) ) {
    set_kb_item( name:"telnet/netgear/prosafe/detected", value:TRUE );
    guess += '\n- NETGEAR ProSAFE Device';
  }

  if( "Hirschmann Automation and Control GmbH" >< banner ) {
    set_kb_item( name:"telnet/hirschmann/device/detected", value:TRUE );
    guess += '\n- Hirschmann Device';
  }

  if( "Rugged Operating System" >< banner || "Command Line Interface RUGGEDCOM" >< banner ) {
    set_kb_item( name:"telnet/siemens/ruggedcom/detected", value:TRUE );
    guess += '\n- Siemens Rugged Operating System/RUGGEDCOM';
  }

  if( "SIMATIC NET" >< banner || "SCALANCE" >< banner ) {
    set_kb_item( name:"telnet/siemens/scalance/detected", value:TRUE );
    guess += '\n- Siemens SIMATIC SCALANCE Device';
  }

  if( banner =~ "U1900 OS.*on eSpace" ) {
    set_kb_item( name:"telnet/huawei/espace/detected", value:TRUE );
    guess += '\n- Huawei eSpace Unified Gateway';
  }

  if( "Fabric OS" >< banner ) {
    set_kb_item( name:"telnet/brocade/fabric_os/detected", value:TRUE );
    guess += '\n- Brocade Fabric OS';
  }

  if( banner =~ 'Autonomic Controls' ) {
    set_kb_item( name:"telnet/autonomic_controls/device/detected", value:TRUE );
    guess += '\n- Autonomic Controls Device';
  }

  if( banner =~ '(Shield|Power)Link' ) {
    set_kb_item( name:"telnet/ecessa/shield_power_link/detected", value:TRUE );
    guess += '\n- Ecessa ShieldLink/PowerLink';
  }

  if( "Telemetry Gateway A840" >< banner ) {
    set_kb_item( name:"telnet/adcon/telemetry_gateway_a840/detected", value:TRUE );
    guess += '\n- Adcon A840 Telemetry Gateway';
  }

  if( "Huawei DP300" >< banner ) {
    set_kb_item( name:"telnet/huawei/dp300/detected", value:TRUE );
    guess += '\n- Huawei DP300';
  }

  if( "Bay Networks" >< banner || ( "Passport" >< banner || "NetLogin:" >< banner ) ) {
    set_kb_item( name:"telnet/nortel_bay_networks/device/detected", value:TRUE );
    guess += '\n- Nortel Networks (former Bay Networks) Device';
  }

  if( "Annex" >< banner ) {
    set_kb_item( name:"telnet/nortel_bay_networks/annex/detected", value:TRUE );
    guess += '\n- Nortel Networks (former Bay Networks) Annex';
  }

  if( "@ Userid:" >< banner ) {
    set_kb_item( name:"telnet/shiva/lanrover/detected", value:TRUE );
    guess += '\n- Shiva LanRover';
  }

  if( "Accelar 1200" >< banner ) {
    set_kb_item( name:"telnet/bay_networks/accelar_1200/detected", value:TRUE );
    guess += '\n- Bay Networks Accelar 1200 Switch';
  }

  if( "Ctrl-Y" >< banner || "P Configuration" >< banner ) {
    set_kb_item( name:"telnet/nortel_networks/baystack/detected", value:TRUE );
    guess += '\n- Nortel Baystack Switch';
  }

  if( "Welcome to P330" >< banner ) {
    set_kb_item( name:"telnet/avaya_p330/detected", value:TRUE );
    guess += '\n- Avaya P330 Stackable Switch';
  }

  if( "TELNET session" >< banner ) {
    set_kb_item( name:"telnet/allied/telesyn/detected", value:TRUE );
    guess += '\n- Allied Telesyn Router/Switch';
  }

  if( banner =~ "GE.*SNMP/Web Interface" && "UPS" >< banner ) {
    set_kb_item( name:"telnet/ge/snmp_web_iface_adapter/detected", value:TRUE );
    guess += '\n- GE SNMP/Web Interface Adapter';
  }

  if( banner =~ "SoftCo OS" ) {
    set_kb_item( name:"telnet/huawei/softco/detected", value:TRUE );
    guess += '\n- Huawei SoftCo';
  }

  if( "Welcome to Microsoft Telnet Service" >< banner ) {
    set_kb_item( name:"telnet/microsoft/telnet_service/detected", value:TRUE );
    guess += '\n- Microsoft Windows Telnet Service';
  }

  if( "KERI-ENET" >< banner ) {
    set_kb_item( name:"telnet/keri_systems/access_control_system/detected", value:TRUE );
    guess += '\n- Keri Systems Access Control System';
  }

  if( "izon login" >< banner ) {
    set_kb_item( name:"telnet/izon/ip_camera/detected", value:TRUE );
    guess += '\n- IZON IP Camera';
  }

  if( "SCALANCE X200" >< banner ) {
    set_kb_item( name:"telnet/siemens/scalance_x200/detected", value:TRUE );
    guess += '\n- Siemens Scalance X200';
  }

  if( "Blackboard LC3000" >< banner ) {
    set_kb_item( name:"telnet/blackboard/lc3000/detected", value:TRUE );
    guess += '\n- Blackboard LC3000 Laundry Reader';
  }

  if( "insight login" >< banner ) {
    set_kb_item( name:"telnet/philips/in_sight/detected", value:TRUE );
    guess += '\n- Philips In.Sight';
  }

  if( "Welcome. Type <return>, enter password at # prompt" >< banner ) {
    set_kb_item( name:"telnet/brother/device/detected", value:TRUE );
    guess += '\n- Multiple Brother Devices';
  }

  if( "ZEM" >< banner ) {
    set_kb_item( name:"telnet/fingertex/device/detected", value:TRUE );
    guess += '\n- FingerTec Device';
  }

  if( "Polycom Command Shell" >< banner || "Welcome to ViewStation" >< banner || ( "Hi, my name is" >< banner && "Here is what I know about myself" >< banner ) ) {
    set_kb_item( name:"telnet/polycom/device/detected", value:TRUE );
    guess += '\n- Polycom Device';
  }

  if( "PK5001Z login:" >< banner || "BCM963268 Broadband Router" >< banner ) {
    set_kb_item( name:"telnet/zyxel/modem/detected", value:TRUE );
    guess += '\n- ZyXEL PK5001Z or C1100Z Modem';
  }

  if( "===Actiontec xDSL Router===" >< banner ) {
    set_kb_item( name:"telnet/actiontec/modem/detected", value:TRUE );
    guess += '\n- Actiontec Modem';
  }

  if( banner =~ "Welcome to (ZXUN|ZXR10).+ of ZTE Corporation" ) {
    set_kb_item( name:"telnet/zte/zxr10/detected", value:TRUE );
    guess += '\n- ZTE ZXR10 Router';
  }

  if( "ManageUPSnet" >< banner ) {
    set_kb_item( name:"telnet/manageupsnet/detected", value:TRUE );
    guess += '\n- ManageUPSNET UPS / USV';
  }

  if( banner =~ "TANDBERG Codec Release" ) {
    set_kb_item( name:"telnet/tandberg/device/detected", value:TRUE );
    guess += '\n- Tandberg Device';
  }

  if( "Netsynt " >< banner ) {
    set_kb_item( name:"telnet/netsynt/crd_voice_router/detected", value:TRUE );
    guess += '\n- Netsynt CRD Voice Router';
  }

  if( egrep( string:banner, pattern:"pCOWeb[^ ]* login:", icase:FALSE ) ) {
    set_kb_item( name:"telnet/carel/pcoweb/detected", value:TRUE );
    guess += '\n- CAREL pCOWeb Device';
  }

  if( "BusyBox" >< banner || "list of built-in commands" >< banner ) {
    set_kb_item( name:"telnet/busybox/console/detected", value:TRUE );
    guess += '\n- BusyBox Telnet Console';
  }

  if( "IPmux-2L" >< banner ) {
    set_kb_item( name:"telnet/ipmux-2l/tdm/detected", value:TRUE );
    guess += '\n- IPmux-2L TDM Pseudowire Access Gateway';
  }

  if( banner == '\r\nToo many users logged in!  Please try again later.\r\n' || banner =~ '^\r\n\r\nData ONTAP' ) {
    set_kb_item( name:"telnet/netapp/data_ontap/detected", value:TRUE );
    guess += '\n- NetApp Data ONTAP';
  }

  if( "Welcome to the DataStream" >< banner ) {
    set_kb_item( name:"telnet/datastream/detected", value:TRUE );
    guess += '\n- DataStream (DS800) Device';
  }

  if( "(none) login: " >< banner ) {
    set_kb_item( name:"telnet/mult_dvr_or_radio/detected", value:TRUE );
    guess += '\n- DVR or Internet Radio Device of multiple vendors (e.g. TELESTAR-DIGITAL GmbH)';
    guess += '\n- HiSilicon Encoder';
  }

  if( "Digitalisierungsbox" >< banner ) {
    set_kb_item( name:"telnet/digitalisierungsbox/detected", value:TRUE );
    guess += '\n- Digitalisierungsbox STANDARD/BASIC/SMART/PREMIUM';
  }

  if( "SmartLAN login:" >< banner ) {
    set_kb_item( name:"telnet/inim/smartlan/detected", value:TRUE );
    guess += '\n- Inim SmartLAN';
  }

  if( "| LANCOM" >< banner ) {
    set_kb_item( name:"telnet/lancom/detected", value:TRUE );
    guess += '\n- LANCOM Device';
  }

  if( "Draytek login:" >< banner ) {
    set_kb_item( name:"telnet/draytek/detected", value:TRUE );
    guess += '\n- DrayTek Vigor Device';
  }

  # Grandstream GXP2124 Command Shell Copyright 2011
  # Grandstream GXP2000 Command Shell
  # Grandstream GXP1405 Command Shell Copyright 2011
  # Grandstream GXP1200 Command Shell
  if( "Grandstream GXP" >< banner ) {
    set_kb_item( name:"telnet/grandstream/gxp/detected", value:TRUE );
    guess += '\n- Grandstream GXP Series IP Phone';
  }

  if( "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." >< banner || ( "Login authentication" >< banner && "Username:" >< banner ) ) {
    set_kb_item( name:"telnet/huawei/vrp/detected", value:TRUE );
    guess += '\n- Huawei Versatile Routing Platform (VRP)';
  }

  if( "geneko login:" >< banner ) {
    set_kb_item( name:"telnet/geneko/router/detected", value:TRUE );
    guess += '\n- Geneko Router';
  }

  if( "xlweb login:" >< banner ) {
    set_kb_item( name:"telnet/honeywell/excel_web/detected", value:TRUE );
    guess += '\n- Honeywell Excel Web Controller';
  }

  if( banner =~ "Welcome to (ZyWALL )?USG ?[0-9]+" ) {
    set_kb_item( name:"telnet/zyxel_usg/detected", value:TRUE );
    guess += '\n- Zyxel USG Device';
  }

  if( banner =~ "JAMES Remote Administration Tool" ) {
    set_kb_item( name:"telnet/apache/james_server/detected", value:TRUE );
    guess += '\n- Apache James Server';
  }

  if( banner =~ "Nexus [0-9]+ Switch" ) {
    set_kb_item( name:"telnet/cisco/nx_os/detected", value:TRUE );
    guess += '\n- Cisco Nexus Switch';
  }

  if( "Ubiquiti Networks" >< banner && "Welcome to EdgeOS" >< banner ) {
    set_kb_item( name:"telnet/ubiquiti/edgerouter/detected", value:TRUE );
    guess += '\n- Ubiquiti EdgeRouter';
  }

  if( "FreeBSD" >< banner ) {
    set_kb_item( name:"telnet/freebsd/detected", value:TRUE );
    guess += '\n- FreeBSD';
  }

  # (Cisco Controller)
  # User: Raw mode will not be supported, Closing connection.
  #
  # User:
  if( "(Cisco Controller)" >< banner ) {
    set_kb_item( name:"telnet/cisco/wlc/detected", value:TRUE );
    guess += '\n- Cisco Wireless LAN Controller (WLC)';
  }

  if( "WagoIPC1 login" >< banner ) {
    set_kb_item( name:"telnet/wago/detected", value:TRUE );
    guess += '\n- WAGO I/O System 758 series device';
  }

  if( banner =~ "FortiADC" ) {
    set_kb_item( name:"telnet/fortinet/fortiadc/detected", value:TRUE );
    guess += '\n- Fortinet FortiADC';
  }

  if( banner =~ "telnet session telnet[0-9]+ on /dev/ptyb[0-9]+" ) {
    set_kb_item( name:"telnet/extreme/exos/detected", value:TRUE );
    guess += '\n- Extreme Networks EXOS Switch';
  }

  if( banner =~ "Welcome on mldonkey command-line" ) {
    set_kb_item( name:"telnet/mldonkey/detected", value:TRUE );
    guess += '\n- MLDonkey';
  }

  if( banner =~ "^EVENT" && "WatchGuard Authentication Gateway SSO agent" >< banner ) {
    set_kb_item( name:"telnet/watchguard/sso_agent/detected", value:TRUE );
    guess += '\n- WatchGuard SSO Agent';
  }

  if( banner =~ "VMG[0-9]{4}\-[A-Z][[0-9].*(login|Username)" || banner =~ "(ZyXEL[^ ]* )?SBG[0-9]{4}") {
    set_kb_item( name:"telnet/zyxel/router/detected", value:TRUE );
    guess += '\n- Zyxel Router';
  }

  if( banner =~ "cnPilot\-[^ ]+ login:" ) {
    set_kb_item( name:"telnet/cambium/cnpiloit/detected", value:TRUE );
    guess += '\n- Cambium cnPilot';
  }

  # e.g.:
  #
  # MINI-LINK 6600  Command Line Interface
  #
  # or:
  #
  # \r\r\n\r\nCLI master busy. Only one session allowed.\r\n\r\nPlease try again later.\r\n\r\n
  #
  # nb: Keep the pattern in sync with the ones in:
  # - telnetserver_detect_type_nd_version.nasl
  # - gsf/gb_ericsson_mini-link_telnet_detect.nasl
  #
  if( egrep( string:banner, pattern:"(MINI-LINK.+Command Line Interface|CLI master busy\. Only one session allowed\..*Please try again later\.)", icase:FALSE ) ) {
    set_kb_item( name:"telnet/ericsson/mini-link/detected", value:TRUE );
    guess += '\n- Ericsson MINI-LINK Device';
  }

  report = 'Remote Telnet banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably (a):\n' + guess;

  if( strlen( fragile ) > 0 )
    report += fragile;

  log_message( port:port, data:report );
}

exit( 0 );
