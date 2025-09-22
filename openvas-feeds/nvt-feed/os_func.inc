# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns the CPE of the "best" determined operating system running on the remote host.
#
# @note You need to add a dependency to the VT "os_detection.nasl" for this function.
#
# @return A string containing the CPE of the "best" OS, NULL if it wasn't possible to determine the best one.
#
function os_get_best_cpe() {

  local_var best_os_cpe;

  best_os_cpe = get_kb_item( "HostDetails/OS/BestMatchCPE" );
  if( best_os_cpe )
    return best_os_cpe;

  return NULL;
}

# @brief Returns the name (text form) of the "best" determined operating system running on the remote host.
#
# @return A string containing the name of the "best" OS, NULL if it wasn't possible to determine the best one.
#
function os_get_best_txt() {

  local_var best_os_txt;

  best_os_txt = get_kb_item( "HostDetails/OS/BestMatchTXT" );
  if( best_os_txt )
    return best_os_txt;

  return NULL;
}

# @brief Returns the info if the operating system of the remote host is matching a specified pattern.
#
# @param _FCT_ANON_ARGS[0] The pattern to match against the remote operating system.
#
# @return "yes" if the remote operating system is matching the specified ospattern, "no" not matching or
#         "unknown" in other cases where it wasn't possible to determine the status of the OS.
#
function os_host_runs() {

  local_var ospattern, best_os;

  ospattern = _FCT_ANON_ARGS[0];
  if( ! ospattern )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#os_host_runs" );

  #TBD/TODO: What if "os_get_best_txt" is "better" then "os_get_best_cpe"?
  best_os = os_get_best_cpe();
  if( isnull( best_os ) ) {
    best_os = os_get_best_txt();
    if( isnull( best_os ) )
      return "unknown";
  }

  #nb: update this to include possible cpes and txt (name in text form) from ssh_detect.nasl, gb_ssh_os_detection.nasl, gather-package-list.nasl and other *_os_detection.nasl
  if( "linux" >< tolower( ospattern ) )
    ospattern = '(' + ospattern + '|apc:aos|ubuntu|debian|bsd|opensuse|fedora|suse|red ?hat|centos|mandriva|mandrake|mageia|slackware|conectiva|amazon|oracle|d-?link(:| ).+firmware|euleros|openeuler|' +
                'turbolinux|gentoo|cisco|apple|fortios|junos|screenos|univention|esx|xen|pan-?os|qnap|synology|greenbone|hyperip|simatic|rugged(_| )operating(_| )system|vibnode|avm(:| )fritz|(my|wd)(_| )cloud|' +
                'intelbras(:| )ncloud|ricoh:iwb|nucleus(_| )rtos|vxworks|chip-rtos|simatic(_| )hmi|ibm(:| )os(/|_)400|novell|rockwell ?automation(:| )(micrologix|powermonitor)|beward|' +
                'tippingpoint(_| )operating(_| )system|data(_| )ontap|(zavio|tp-link|pearl|qsee)(:| )ip(_| )camera|riverbed(_| )optimization(_| )system|synetica(:| )datastream|' +
                'ricoh(:| ).+_firmware|lexmark(:| ).+_firmware|:wlan_controller_ap_firmware|zyxel(:| ).+_firmware|toshiba(:| ).+_firmware|moxa(:| )(edr|iologik)|sangoma(:| ).+(_| )firmware|' +
                'silver(-| )peak(:| )(unity_edgeconnect|nx|vx|unknown_model)_sd-wan_firmware|ewon(:| ).+_firmware|optergy(:| )proton(_| )firmware|digitalisierungsbox|base(_| )station(_| )firmware|' +
                'smartlan(_g_| )firmware|unitronics(_| ).+_firmware|ruckuswireless.+(_| )firmware|ip-ak2(_| )firmware|lancom(:| ).+(_| )firmware|timetools(:| ).+(_| )firmware|' +
                'unraid:unraid|arubanetworks(:| )instant|arubanetworks:.+(_| )firmware|aruba/hpe.+ firmware|sonicwall(:| )|xerox(:| ).+(_| )firmware|moxa(:| ).+(_| )firmware|circontrol(:| )(circarlife|raption)(_| )firmware|' +
                'barracuda(:| )load( )?balancer|grandstream(:| ).+(_| )firmware|huawei.+firmware|draytek(:| ).+(_| )firmware|(isilon|powerscale)(_| )onefs|vicon(_| )industries(:| ).+(_| )firmware|' +
                'auerswald(:| ).+firmware|hpe(:| )onboard(_| )administrator(_| )firmware|sophos(:| )(sfos|firewall)|brickcom|xg(:| ).+(_| )firmware|cnpilot.+(_| )firmware|geneko(_| )router|' +
                'cloudgate.+firmware|sato(:| ).+(_| )firmware|konicaminolta(:| ).+(_| )firmware|gpon(:| ).+(_| )firmware|teltonika(:| ).+(_| )firmware|axis(:| ).+(_| )firmware|znid(_| ).*(_| )firmware|' +
                'yealink(:| )(vo)?ip(_| )phone|officeconnect.*firewall(_| )software|phoenix(_| )contact(:| ).+firmware|honeywell(:| ).*controller|buffalo(:| ).+firmware|linksys(:| ).+firmware|' +
                'intel(:| )standard(_| )manageability|mobileiron(:| )(core|sentry)|edgecore(:| )es3526xa|spinetix(:| ).+firmware|ruckus.*(:| )iot(_| )controller|westermo(:| )weos|netgear(:| )|contiki(-| )os|' +
                'nut(/|_)os|ui(:| ).*(_| )firmware|zyxel(:| ).*firmware|loxone(:| )miniserver|abb(:| ).*firmware|schneider(-| )electric(:| )powerlogic|tp-link|ups(:| ).*firmware|photon(_| )os|avtech|' +
                'garrettcom(:| )|siemens(:| ).*firmware|flir(:| )(ax8|neco(_| )platform)(_| )firmware|maipu(:| ).*firmware|ibm(:| )global(_| )console|easyio(:| )|(sma_solar_technology_ag|sma solar sunny)|' +
                'western(_| )digital(:| )my(_| )book(_| )live(_| )firmware|seagate(:| ).*firmware|epson(:| ).+firmware|ruijie(_| )networks(:| ).*firmware|canon(:| ).+firmware|kyocera(:| ).+firmware|' +
                'hp(:| ).+firmware|watchguard(:| )fireware|sony(:| )network.+camera.+firmware|turck(:| ).+firmware|franklinfueling(:| ).+firmware|quest(:| )kace|3com(:| ).+firmware|contec(:| )sv-cpt.+firmware' +
                'arris(:| ).+firmware|hikvision(:| )ip(_| )camera(_| )firmware)|barracuda(:| )cloudgen.+firmware|cradlepoint.+firmware|octopi|technicolor(:| )tc7200|sharp(:| ).+firmware|f5(:| ).*lros|' +
                'hpe(:| )officeconnect.+firmware|cyberoam(_| )os|optilink(:| )switch(_| )firmware|rocky(:| )(rocky|linux)|alma ?linux|barox(:| ).+firmware|meinberg.*(:| )lantime(_| )firmware|terramaster(:| ).+firmware|' +
                'axis( |_)os|alcatel-lucent(:| ).+firmware|riello(:| )netman(_| )204(_| )firmware|home-assistant:home-assistant|home assistant os|arrayos|apsystems(:| )energy(_| )communication(_| )unit(_| )firmware|' +
                '(brocade|broadcom).+fabric|barracuda(:| )email_security_gateway|edge-?core.+firmware|fujifilm(:| ).+(_| )firmware|vmware(:| ).+firmware|rockwell ?automation(:| ).+firmware|mitel(:| ).+firmware|brother(:| ).+firmware|polycom( |:)unified( |_)communications( |_)software|supermicro(:| ).+firmware|sangfor.+ngaf.+firmware|honeywell.+firmware|' +
                'extreme ?networks(:| ).+exos|trendnet(:| ).+( |_)firmware|viessmann(:| )vitogate.+( |_)firmware|dell(:| ).+firmware|sierra ?wireless(:| )aleos|gl(\\.|-)inet(:| ).+( |_)firmware|netis(-systems)?(:| ).+firmware|inotec(:| ).+( |_)firmware|' +
                'f5(:| )f5os|huawei(:| )yunsha(_| )os|dell(:| )emc( |_)(networking|smartfabric)( |_)os10|juniper(:| ).+firmware|schneider(-| )electric(:| ).*(_| )firmware|(hp:|poly ).*(_| )firmware|four-faith(:| ).+firmware|junos( |_space)|kerio(:| )control|' +
                'fortinet(:| )fortinac-os|audiocodes(:| ).*(_| )firmware|fortinet(:| )fortiswitch|bomgar(:| ).+base(_| )software|unifi(_| )os|' +
                'vertiv(:| ).*(_| )firmware|tandberg(:| )device(_| )firmware|(edimax|logitec|elecom|iodata)(:| ).+firmware|tp-link(:| ).+firmware|ericsson(:| )mini(_|-)link.+firmware|' +
                'bap(-| )technologie(:| ).+firmware|advantech(:| ).+firmware|hpe(:| ).+firmware|sonos(:| ).+firmware|ptzoptics(:| ).+firmware|fxc(:| ).+firmware)';

  if( eregmatch( pattern:ospattern, string:best_os, icase:TRUE ) )
    return "yes";

  return "no";
}

# @brief Registers and reports a detected operating system of the remote host.
#
# @param os          The name of the OS to register.
# @param version     The version of the OS to register.
# @param patch       The update- / patch-level of the OS to register.
# @param cpe         The CPE of the OS to register
# @param banner_type The type of the banner where the OS was detected from, e.g "HTTP Banner".
# @param port        The port of the OS to register.
# @param proto       The protocol of the OS to register. Defaults to "tcp" if not passed.
# @param banner      The banner of the OS where the OS was detected from.
# @param desc        The description of the VT (e.g. script_name()) registering the OS
# @param runs_key    The "runs_key" which should be used to register the OS as, currently supported: "windows" or "unixoide".
# @param full_cpe    Flag to determine whether the CPE is fully set and already includes the version and/or patch.
#
# @return NULL
#
function os_register_and_report( os, version, patch, cpe, banner_type, port, proto, banner, desc, runs_key, full_cpe ) {

  local_var os, version, patch, cpe, banner_type, port, proto, banner, desc, runs_key, full_cpe;
  local_var oid, malformed_cpe, report, version_lo, patch_lo;

  oid = get_script_oid();

  if( cpe && ! get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#os_register_and_report()#-#" + cpe + "#-#cpe" );
    malformed_cpe = TRUE;
  }

  if( ! proto )
    proto = "tcp";

  if( ! desc )
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#desc#-#os_register_and_report" );

  if( strlen( os ) > 0 ) {
    # nb: The check for "version >!< os" is to avoid that the version number is added if it was
    # already included in the "os" function parameter (shouldn't happen but just to be sure...)
    if( strlen( version ) > 0 && tolower( version ) != "unknown" && version >!< os )
      os += " " + version;

    register_host_detail( name:"OS", value:os, desc:desc );
  } else {
    os = "N/A";
  }

  report = 'OS:           ' + os;

  if( version && tolower( version ) != "unknown" ) {

    version_lo = tolower( version );

    report += '\nVersion:      ' + version;

    if( cpe && ! full_cpe && ! malformed_cpe )
      cpe += ":" + version_lo;
  }

  if( patch && tolower( patch ) != "unknown" ) {

    patch_lo = tolower( patch );

    report += '\nPatch/Update: ' + patch;

    if( cpe && ! full_cpe && ! malformed_cpe ) {
      if( version && tolower( version ) != "unknown" )
        cpe += ":" + patch_lo;
      else
        cpe += "::" + patch_lo;
    }
  }

  if( cpe && ! malformed_cpe )
    register_host_detail( name:"OS", value:cpe, desc:desc );
  else
    cpe = "N/A";

  report += '\nCPE:          ' + cpe;
  report += '\nFound by VT:  ' + oid + ' (' + desc + ')';

  if( banner_type ) {

    report += '\nConcluded from ' + banner_type;

    if( port && proto != "icmp" )
      report += " on port " + port + "/" + proto;

    if( banner ) {
      banner = chomp( banner ); # Few banners have newlines at the end so removing these here
      report += ': ' + banner;
    }
  }

  # Keep down here as we only need this defaults for the set_kb_item
  if( ! port )
    port = "0";

  set_kb_item( name:"os_detection_report/reports/" + oid + "/" + port + "/" + proto, value:report );

  # For setting the "Host/runs_windows" or "Host/runs_unixoide" key in os_detection.nasl
  if( ! isnull( runs_key ) )
    set_kb_item( name:"os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value:runs_key );
  else
    set_kb_item( name:"os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value:"unknown" );
}

# @brief Registers an unknown banner in the KB which could contain info to detect an operating
#        system for later reporting within gb_unknown_os_service_reporting.nasl
#
# @param banner            the banner to register. Required.
# @param banner_type_name  short description of the banner (e.g. HTTP banner) which is included
#                          in the later reporting. Required.
# @param banner_type_short short keyword (e.g. http_banner) which is used internally as a keyword
#                          for the KB key where the information is saved at. Required.
# @param port              port (optional) where the banner was identified at, defaults to "0" if empty.
# @param proto             protocol (optional, tcp or udp) where the banner was identified at, defaults
#                          to "tcp" if empty.
#
# @return NULL
#
function os_register_unknown_banner( banner, banner_type_name, banner_type_short, port, proto ) {

  local_var banner, banner_type_name, banner_type_short, port, proto;
  local_var oid;

  oid = get_script_oid();

  if( ! banner ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner#-#os_register_unknown_banner" );
    return;
  }

  if( ! banner_type_name ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner_type_name#-#os_register_unknown_banner" );
    return;
  }

  if( ! banner_type_short ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner_type_short#-#os_register_unknown_banner" );
    return;
  }

  banner = chomp( banner ); # Few banners have newlines at the end so removing these here

  # Don't report known banner were we know that it doesn't contain info about an OS here
  if( banner == "login:" ||
      egrep( pattern:"^MikroTik ", string:banner ) || # Already covered by gb_mikrotik_router_routeros_consolidation.nasl
      egrep( pattern:"^[0-9.]+$", string:banner ) ) { # Bind9 and MySQL. Both are often only sending e.g. 9.4.2
    return;
  }

  if( ! proto )
    proto = "tcp";

  if( ! port )
    port = "0";

  set_kb_item( name:"os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/banner", value:banner );
  set_kb_item( name:"os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/type_full", value:banner_type_name );
  set_kb_item( name:"unknown_os_or_service/available", value:TRUE ); # Used in gb_unknown_os_service_reporting.nasl
}

# @brief Evaluates if the passed list contains at least one element of the same type (cpe or text).
#        TODO: Not really sure what the functions is actually doing / responsible for...
#
# @param oslist A list of operating system CPEs to match against.
# @param bestos The CPE of the current "Best OS" registered.
#
# @return TRUE if the list contains at least one element of the same type (cpe or text), FALSE otherwise.
#
function os_conflict( oslist, bestos ) {

  local_var oslist, bestos, is_cpe, _item;

  is_cpe = FALSE;

  if( "cpe:/" >< bestos )
    is_cpe = TRUE;

  foreach _item( oslist ) {
    if( _item == bestos )
      continue;

    # return true if the list contains at least one element of the same type (cpe or text)
    if( ( "cpe:/" >< _item ) == is_cpe )
      return TRUE;
  }
  return FALSE;
}

# @brief Registers the CPE of the "best" determined operating system running on the remote host as a
#        HostDetail.
#
# @note You need to add a dependency to the VT "os_detection.nasl" for this function.
#
# @return NULL
#
function os_report_best_cpe() {

  local_var best_os_cpe, desc;

  best_os_cpe = os_get_best_cpe();
  if( best_os_cpe ) {
    desc = get_kb_item( "HostDetails/OS/BestMatchCPE/Details" );
    desc = split( desc, sep:";" );
    report_host_detail_single( name:"best_os_cpe", value:best_os_cpe, nvt:desc[0], desc:desc[1] );
  }

  return NULL;
}

# @brief Registers the name (text form) of the "best" determined operating system running on the
#        remote host as a HostDetail.
#
# @note You need to add a dependency to the VT "os_detection.nasl" for this function.
#
# @return NULL
#
function os_report_best_txt() {

  local_var best_os_txt, desc;

  # TODO: In earlier versions of this function it was checked if there is a "os conflict" via a code like e.g.:
  #
  # if( os_conflict( oslist:res, bestos:best_os ) )
  #   best_os = best_os + ' [possible conflict]';
  #
  # Once os_detection.nasl was updated to handle/register multiple OS detections from the same Detection-VT
  # we should re-introduce such a "os_conflict" check again.
  #
  # nb: For some reason src/manage_sql.c of gvmd is only checking for the [possible conflict] text in best_os_txt.
  best_os_txt = os_get_best_txt();
  if( best_os_txt ) {
    desc = get_kb_item( "HostDetails/OS/BestMatchTXT/Details" );
    desc = split( desc, sep:";" );
    report_host_detail_single( name:"best_os_txt", value:best_os_txt, nvt:desc[0], desc:desc[1] );
  }

  return NULL;
}

# @brief Returns the list of OIDs of VTs doing CPE based OS detection. The list is sorted by
#        decreasing accuracy (best is first).
#
# @return The list of OIDs of VTs as described in the function description.
#
function os_get_cpe_src_list() {

  local_var oid_list;

  oid_list = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810231", # gb_apple_macosx_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149245", # gsf/gb_vmware_esxi_openslp_udp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149705", # gsf/gb_vmware_esxi_openslp_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150826", # gsf/gb_vmware_sdwan_edge_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96206",  # gb_ssh_cisco_ios_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105544", # gb_cisco_cucmim_version.nasl
    "1.3.6.1.4.1.25623.1.0.147755", # gb_cisco_cucm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105690", # gb_cisco_nx_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105068", # gb_cyclades_detect.nasl
    # nb: The FortiGate VT should be before all other Fortinet VTs registering FortiOS because it is
    # currently registering the FortiOS version as well.
    "1.3.6.1.4.1.25623.1.0.147797", # gb_fortinet_fortigate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105313", # gb_fortinet_fortios_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144208", # gb_fortinet_fortimail_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149328", # gsf/gb_fortinet_fortiadc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149332", # gsf/gb_fortinet_fortinac_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171155", # gsf/gb_fortinet_fortiswitch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170963", # gb_fortinet_fortiweb_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114880", # gb_fortinet_fortimanager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171017", # gb_fortinet_fortianalyzer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105440", # gb_cisco_esa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105441", # gb_cisco_wsa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105433", # gb_cisco_csma_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105533", # gb_cisco_ip_phone_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105532", # gb_cisco_ios_xr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146071", # gsf/gb_cisco_sdwan_vedge_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149142", # gb_juniper_junos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153760", # gb_juniper_junos_space_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152516", # gsf/gb_juniper_ssr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105263", # gb_paloalto_panos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114574", # gsf/gb_f5_big-ip_next_central_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114597", # gsf/gb_f5_big-ip_next_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114573", # gsf/gb_f5_f5os_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142605", # gsf/gb_paloalto_globalprotect_portal_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105266", # gb_screenos_version.nasl
    "1.3.6.1.4.1.25623.1.0.151229", # gb_extremeos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152371", # gsf/gb_dell_emc_smartfabric_os10_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108566", # gb_tippingpoint_sms_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106513", # gb_cisco_asa_version_snmp.nasl
    "1.3.6.1.4.1.25623.1.0.105222", # gb_cisco_asa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105033", # gb_cisco_asa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153239", # gsf/gb_cisco_meraki_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105430", # gb_cisco_wlc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143118", # gb_f5_big_iq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104593", # gb_riello_ups_netman_204_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144335", # gsf/gb_secomea_gatemanager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106494", # gb_arista_eos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149143", # gsf/gb_barox_switch_snmp_detection.nasl
    "1.3.6.1.4.1.25623.1.0.151625", # gsf/gb_glinet_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149387", # gsf/gb_alcatel_omniswitch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153343", # gsf/gb_elvaco_cme_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108307", # gb_netgear_prosafe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141740", # gb_netgear_wnap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146185", # gb_netgear_smart_cloud_switch_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107228", # gb_netgear_dgn2200_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112334", # gb_netgear_dgnd3700_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141679", # gb_wd_mybook_live_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153820", # gb_kerio_control_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108311", # gb_hirschmann_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154741", # gsf/gb_abb_eibport_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140590", # gb_phoenix_fl_comserver_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149706", # gsf/gb_phoenixcontact_plc_device_pcworx_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154823", # gsf/gb_advantech_wise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153980", # gsf/gb_audiocodes_sbc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144115", # gb_geneko_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143245", # gsf/gb_unitronics_plc_pcom_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144128", # gb_option_cloudgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810608", # gb_mikrotik_router_routeros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.113169", # gb_gpon_home_router_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145096", # gsf/gb_zyxel_usg_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148200", # gsf/gb_zyxel_atp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148183", # gsf/gb_zyxel_vpn_firewall_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148210", # gsf/gb_zyxel_nxc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148242", # gsf/gb_zyxel_nap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148259", # gsf/gb_zyxel_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148282", # gsf/gb_zyxel_nwa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148349", # gsf/gb_zyxel_wac_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148397", # gsf/gb_zyxel_wax_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148479", # gsf/gb_zyxel_uag_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148721", # gb_zyxel_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153896", # gb_zyxel_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154134", # gsf/gb_ubiquiti_unifi_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.155109", # gsf/gb_ubiquiti_edgeswitch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140540", # gb_sitefinity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150750", # gsf/gb_contec_solarview_compact_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144354", # gb_zhone_znid_gpon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143523", # gsf/gb_aruba_switches_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149463", # gsf/gb_arrayos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141648", # gb_teltonika_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106833", # gb_garrettcom_switch_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103710", # gb_3com_officeconnect_vpn_firewall_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149276", # gb_hpe_officeconnect_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.155002", # gsf/gb_hpe_instant_on_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155011", # gsf/gb_hpe_instant_on_switch_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148296", # gsf/gb_hp_3com_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170300", # gb_axis_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105144", # gb_xenserver_version.nasl
    "1.3.6.1.4.1.25623.1.0.105659", # gb_cisco_ios_xe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144170", # gb_cisco_nam_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144402", # gb_cisco_small_business_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147593", # gb_cisco_small_business_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145983", # gsf/gb_cisco_hyperflex_data_platform_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117529", # gsf/gb_circontrol_circarlife_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117533", # gsf/gb_circontrol_raption_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147867", # gb_sophos_xg_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105155", # gb_mcafee_email_gateway_version.nasl
    "1.3.6.1.4.1.25623.1.0.140058", # gb_brocade_netiron_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108335", # gb_brocade_fabricos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105244", # gb_aruba_arubaos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146362", # gsf/gb_aruba_instant_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106864", # gb_sophos_cyberoam_utm_ngfw_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106875", # gb_aerohive_hiveos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103875", # gb_qnap_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170202", # gb_synology_dsm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170230", # gb_synology_srm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142078", # gb_drobo_nas_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140995", # gb_buffalo_airstation_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153874", # gb_unraid_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103753", # gb_seagate_blackarmor_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106840", # gb_terramaster_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112353", # gb_buffalo_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149001", # gb_seagate_central_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.805964", # gb_netsweeper_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811915", # gb_trendmicro_smart_protection_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149991", # gsf/gb_citrix_sharefile_storagezones_controller_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148299", # gsf/gb_citrix_adm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106151", # gb_barracuda_load_balancer_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149737", # gsf/gb_barracuda_email_security_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142729", # gsf/gb_fortinet_fortios_sslvpn_portal_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106096", # gb_siemens_simatic_s7_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140738", # gb_simatic_cp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145830", # gb_simatic_scalance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140811", # gb_siemens_ruggedcom_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151045", # gsf/gb_siemens_logo_plc_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142907", # gsf/gb_ewon_flexy_cosy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143136", # gsf/gb_optergy_proton_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144491", # gb_honeywell_xlweb_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146123", # gsf/gb_schneider_powerlogic_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152659", # gsf/gb_schneider_modicon_controller_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152727", # gsf/gb_schneider_powerlogic_protection_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142369", # gb_easyio_30p_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141019", # gb_sonos_upnp_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155013", # gb_sonos_device_airplay_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152044", # gsf/gb_inotec_cps_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.20285",  # ilo_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105176", # gb_ibm_gcm_kvm_webinterface_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147702", # gb_watchguard_firebox_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108338", # gb_vibnode_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108347", # gb_hyperip_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143323", # gb_ruckus_unleashed_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143341", # gsf/gb_ruckus_zonedirector_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148924", # gsf/gb_ruckus_virtual_smartzone_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148928", # gsf/gb_ruckus_smartzone_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149192", # gsf/gb_ruckus_smartcell_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103910", # gb_avm_fritz_box_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142677", # gb_avm_fritz_wlanrepeater_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143196", # gb_digitalisierungsbox_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143419", # gb_lancom_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143663", # gb_draytek_vigor_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103794", # gb_hp_onboard_administrator_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144339", # gb_cisco_ata_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106216", # gb_cisco_spa_voip_device_sip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113281", # gb_yealink_ip_phone_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151013", # gsf/gb_polycom_ipphone_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153565", # gsf/gb_poly_videoconference_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117074", # gb_dlink_dsr_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170325", # gb_dlink_dap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170779", # gb_dlink_dhp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171557", # gb_dlink_dsl_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106015", # gb_dlink_dns_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170244", # gb_dlink_dir_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171565", # gb_dlink_dwr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171562", # gb_dlink_dcs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170280", # gsf/gb_dlink_dnh_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170349", # gsf/gb_dlink_generic_device_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107252", # gb_dgs_1500_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107300", # gb_trendnet_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811880", # gb_tp_link_routers_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171697", # gb_fxc_router_http_detect.nasl
    # nb: Needs to be after all D-Link detections above because this *might* only register an
    # unknown model while the others above could be more detailed...
    "1.3.6.1.4.1.25623.1.0.170206", # gsf/gb_dlink_devices_hnap_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170243", # gsf/gb_dlink_devices_upnp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170242", # gsf/gb_dlink_devices_mdns_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144526", # gb_linksys_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148591", # gb_arris_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108488", # gb_wd_mycloud_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152791", # gb_sangoma_sbc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108491", # gb_intelbras_ncloud_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141923", # gb_netapp_data_ontap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143673", # gb_emc_isilon_onefs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112339", # gb_brickcom_network_camera_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155078", # gb_ptzoptics_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142807", # gb_ricoh_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141736", # gb_ricoh_iwb_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142838", # gb_lexmark_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142901", # gb_toshiba_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141824", # gb_xerox_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170523", # gb_fujifilm_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112774", # gb_sato_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112777", # gsf/gb_konicaminolta_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146406", # gb_epson_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147494", # gb_canon_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147517", # gb_kyocera_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147610", # gb_hp_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149040", # gb_sharp_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170550", # gb_brother_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151376", # gb_dell_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108494", # gb_codesys_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106075", # gb_sierrawireless_acemanager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144306", # gsf/gb_nimbus_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.141684", # gb_simatic_hmi_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141766", # gb_wago_plc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145363", # gsf/gb_abb_ac500_opcua_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153384", # gsf/gb_abb_aspect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141772", # gb_rockwell_micrologix_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142010", # gb_rockwell_powermonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150832", # gsf/gb_rockwell_controllogix_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154027", # gsf/gb_rockwell_guardlogix_ethernetip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154155", # gsf/gb_liebert_crv_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142684", # gb_crestron_airmedia_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141365", # gb_crestron_cip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141174", # gb_crestron_ctp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147924", # gsf/gb_turck_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.113953", # gsf/gb_franklin_fueling_systems_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113942", # gsf/gb_siemens_sicam_a8000_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808203", # gb_sunny_webbox_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145200", # gb_loxone_miniserver_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114075", # gb_beward_ip_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114095", # gb_zavio_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114097", # gb_tp_link_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808237", # gb_edgecore_ES3526XA_manager_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114099", # gb_pearl_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114000", # gb_qsee_ip_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107335", # gb_vicon_industries_network_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105789", # gb_riverbed_steelcentral_version.nasl
    "1.3.6.1.4.1.25623.1.0.106845", # gb_riverbed_steelhead_ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106844", # gb_riverbed_steelhead_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143317", # gsf/gb_sonicwall_email_security_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143539", # gb_dell_sonicwall_sma_sra_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107120", # gb_sonicwall_ums_gms_analyzer_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146162", # gsf/gb_sonicwall_nsm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106569", # gb_dell_sonicwall_tz_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147864", # gsf/gb_sonicwall_ns_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151575", # gsf/gb_sonicwall_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141135", # gb_quest_kace_sma_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148118", # gb_quest_kace_sda_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143631", # gb_grandstream_ucm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143704", # gb_grandstream_gxp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153692", # gsf/gb_four_faith_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151042", # gb_moxa_edr_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143571", # gb_moxa_iologik_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143598", # gb_moxa_mgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145968", # gb_moxa_nport_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149646", # gb_moxa_miineport_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152565", # gsf/gb_moxa_oncell_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151835", # gb_netis_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151840", # gb_moxa_eds_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151362", # gb_apc_ups_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146507", # gsf/gb_ruijie_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150893", # gsf/gb_mitel_smb_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152413", # gsf/gb_mitel_ip_phones_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140631", # gb_cambium_cnpilot_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143395", # gsf/gb_honeywell_ip-ak2_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147410", # gsf/gb_auerswald_compact_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147412", # gsf/gb_auerswald_commander_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147414", # gsf/gb_auerswald_comfortel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108940", # gsf/gb_spinetix_player_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108943", # gsf/gb_spinetix_fusion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145012", # gsf/gb_contiki_os_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145014", # gsf/gb_ethernut_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106196", # gb_westermo_weos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145072", # gsf/gb_ui_edgepower_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117491", # gsf/gb_maipu_network_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104990", # gsf/gb_honeywell_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117431", # gsf/gb_flir_ax8_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117449", # gsf/gb_flir_a3xx_series_consolidation.nasl
    # nb: Should be below other FLIR detections because we want to use the FLIR camera firmware
    # version as the OS version if possible.
    "1.3.6.1.4.1.25623.1.0.117452", # gsf/gb_flir_neco_platform_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170419", # gsf/gb_apsystems_energy_communication_unit_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112731", # gb_huawei_vrp_network_device_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152275", # gb_huawei_yunshan_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144459", # gb_huawei_ibmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.806636", # gb_huawei_VP9660_mcu_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146155", # gb_huawei_home_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.813817", # gb_avtech_avc7xx_dvr_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809066", # gb_avtech_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149912", # gsf/gb_ubiquiti_edgerouter_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.143355", # gb_huawei_euleros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105614", # gb_cisco_pis_version.nasl
    # nb: This needs to be after gather-package-list.nasl as that is registering the OS in more detail
    "1.3.6.1.4.1.25623.1.0.105522", # gb_cisco_firepower_management_center_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146019", # gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154849", # gb_cisco_ise_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152320", # gb_checkpoint_fw_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112309", # gb_nec_communication_platforms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142731", # gsf/gb_tibco_loglogic_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142733", # gsf/gb_inea_me-rtu_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108632", # gsf/gb_mult_vendors_wlan_controller_aps_detection.nasl
    "1.3.6.1.4.1.25623.1.0.142756", # gsf/gb_dell_emc_powerconnect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142875", # gsf/gb_silverpeak_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143256", # gb_inim_smartlan_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143512", # gsf/gb_timetools_ntp_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143657", # gsf/gb_beckhoff_ads_udp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112771", # gb_dsx_comm_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145540", # gsf/gb_vmware_view_planner_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145934", # gsf/gb_omnissa_workspace_one_uem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148610", # gsf/gb_vmware_hcx_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105862", # gb_vmware_vrealize_operations_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149235", # gb_vmware_vrealize_log_insight_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.111015", # sw_f5_firepass_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105303", # gb_f5_enterprise_manager_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104585", # gb_meinberg_lantime_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.119032", # gsf/gb_ericsson_mini-link_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105586", # gb_ssh_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106030", # gb_accellion_fta_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114106", # gsf/gb_synetica_datastream_devices_telnet_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142620", # gsf/gb_cisco_vision_dynamic_signage_director_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142850", # gsf/gb_cisco_ind_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117048", # gsf/gb_cisco_csm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147479", # gsf/gb_vmware_horizon_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143935", # gb_openvpn_access_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112450", # gb_cradlepoint_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107343", # gb_octopi_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.807073", # gb_sophos_utm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811655", # gb_technicolor_tc7200_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170268", # gb_ispy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170553", # gb_southrivertech_titan_ftp_server_consolidation.nasl
    # nb: The Proxmox and F5 Enterprise Manager VTs were put after gb_ssh_os_detection.nasl because
    # they might only report a generic Debian/CentOS CPE without including the version which would
    # overwrite the SSH one.
    "1.3.6.1.4.1.25623.1.0.117270", # gb_proxmox_ve_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105305", # gb_f5_enterprise_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113756", # gb_cisco_smi_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144350", # gb_pulse_connect_secure_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144140", # gsf/gb_ibm_spectrum_protect_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144152", # gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105271", # gb_citrix_netscaler_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810998", # gb_intel_standard_manageability_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144564", # gb_cisco_ucs_director_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144905", # gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104469", # gsf/gb_barracuda_cloudgen_firewall_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104596", # gsf/gb_barracuda_cloudgen_based_device_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144446", # gsf/gb_vxworks_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144573", # gsf/gb_mobileiron_sentry_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148730", # gsf/gb_cynet_360_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149596", # gb_mailenable_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149618", # gsf/gb_oracle_opera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149660", # gsf/gb_sophos_mobile_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151108", # gsf/gb_supermicro_bmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151265", # gsf/gb_veeam_one_consolidation.nasl
    # nb: The two F5 ones should be before gb_snmp_os_detection.nasl as that one is registering a
    # more generic Linux OS.
    "1.3.6.1.4.1.25623.1.0.105159", # gb_f5_big_ip_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114638", # gsf/gb_f5_big-ip_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108014", # gb_dns_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.105355", # gb_ftp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103979", # gb_ucs_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104498", # gb_cwp_consolidation.nasl
    # nb: Should be before sw_http_os_detection.nasl and gb_microsoft_iis_http_detect.nasl as the
    # devices are emulating an IIS banner which could cause false OS reporting.
    "1.3.6.1.4.1.25623.1.0.104949", # gsf/gb_sangfor_ngaf_http_detect.nasl
    # nb: Should be before sw_http_os_detection.nasl as it detects the Windows OS version in more
    # detail.
    "1.3.6.1.4.1.25623.1.0.900710", # gb_microsoft_iis_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111067", # sw_http_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.100970", # gsf/gb_viessmann_vitogate_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111068", # sw_mail_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111069", # sw_telnet_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108192", # gb_mysql_mariadb_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.100292", # gb_apcnisd_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140184", # gb_dahua_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114084", # gb_amcrest_ip_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108682", # gb_pptp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108590", # gb_ntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # mdns_service_detection.nasl
    "1.3.6.1.4.1.25623.1.0.10144",  # gb_microsoft_sql_server_tcp_ip_listener_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140000", # gb_apple_tv_version.nasl
    "1.3.6.1.4.1.25623.1.0.105899", # gb_apple_tv_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108200", # gb_upnp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108201", # gb_sip_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140096", # gb_checkmk_agent_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100062", # ms_rdp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143777", # gsf/gb_apache_activemq_jms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141106", # gb_schneider_ecostruxure_geo_scada_expert_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107788", # gsf/gb_trendmicro_apex_central_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.118034", # gsf/gb_clickstudios_passwordstate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141987", # gb_suremdm_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108044", # dcetest.nasl
    "1.3.6.1.4.1.25623.1.0.103081", # gb_fsecure_internet_gatekeeper_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.902058", # secpod_ocs_inventory_ng_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144370", # gsf/gb_symantec_endpoint_protection_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108284", # gb_hnap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108565", # gb_ident_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108342", # gb_pi-hole_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105569", # gb_citrix_xenmobile_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117275", # gb_dnsmasq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112869", # gb_dropbear_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141467", # gb_monit_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108451", # gb_rtsp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140337", # gb_netapp_storagegrid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105964", # gb_solarwinds_sam_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151935", # gsf/gb_solarwinds_sem_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151242", # gsf/gb_solarwinds_arm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108455", # gb_nntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106220", # gb_siemens_sinema_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143411", # gsf/gb_siemens_sppa-t3000_app_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105150", # gb_microsoft_exchange_outlook_web_app_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103825", # gb_openvas_manager_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103841", # gb_greenbone_gsa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144367", # gb_aerospike_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100870", # gb_artica_proxy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144839", # gsf/gb_ruckus_iot_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104433", # gsf/gb_bigbluebutton_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112850", # gsf/gb_observium_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145038", # gsf/gb_solarwinds_orion_platform_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145045", # gb_microfocus_filr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145210", # gsf/gb_cisco_dna_center_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146403", # gsf/gb_magicflow_msa_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145205", # gsf/gb_cisco_smart_software_manager_on_prem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145436", # gsf/gb_cisco_sdwan_vmanage_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145298", # gsf/gb_apache_druid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145329", # gb_altn_mdaemon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145380", # gsf/gb_netmotion_mobility_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145395", # gsf/gb_samsung_wlan_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145444", # gsf/gb_nexusdb_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145481", # gsf/gb_rzk_dolusoft_fortilogger_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145485", # gsf/gb_yealink_device_management_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145507", # gsf/gb_inspur_clusterengine_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112873", # gsf/gb_passbolt_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145601", # gsf/gb_netapp_cloud_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117269", # gb_elastix_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145782", # gsf/gb_vmware_workspace_one_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117421", # gsf/gb_kemp_loadmaster_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145924", # gsf/gb_voipmonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150930", # gsf/gb_ivanti_avalanche_consolidation.nasl
    # nb: The CSA one should be after gather-package-list.nasl as the appliance seems to run on CentOS
    "1.3.6.1.4.1.25623.1.0.153131", # gsf/gb_ivanti_cloud_services_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.150958", # gsf/gb_ivanti_epm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151970", # gsf/gb_ivanti_neurons_for_itsm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145946", # gsf/gb_blackberry_uem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142006", # gb_solarwinds_orion_npm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146034", # gb_gate_one_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146046", # gsf/gb_tg8_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146106", # gsf/gb_akkadian_provisioning_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146249", # gsf/gb_dell_wyse_management_suite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106738", # gb_kaseya_vsa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146284", # gsf/gb_philips_vue_pacs_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146322", # gsf/gb_philips_vue_motion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146387", # gsf/gb_elastic_cloud_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146413", # gsf/gb_aapanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146649", # gsf/gb_cisco_firepower_device_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141122", # gb_manageengine_adaudit_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146718", # gsf/gb_manageengine_adselfservice_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146787", # gb_manageengine_admanager_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149108", # gsf/gb_manageengine_ad360_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149111", # gsf/gb_manageengine_endpoint_dlp_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149140", # gsf/gb_manageengine_patch_manager_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141285", # gb_manageengine_exchange_reporter_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146813", # gsf/gb_fatpipe_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140134", # gb_dell_powerscale_insightiq_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146867", # gsf/gb_cisco_intersight_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170134", # gsf/gb_cisco_nexus_dashboard_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.801223", # gb_weborf_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170049", # gb_gitlab_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141670", # gb_veritas_netbackup_appliance_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108191", # gb_sitecore_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117951", # gb_lmtp_service_detect.nasl
    "1.3.6.1.4.1.25623.1.0.125001", # gb_moxa_mxview_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105931", # gb_bmc_trackit_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100405", # gb_zabbix_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147697", # gb_vmware_nsx_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114022", # gb_sony_network_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140809", # gsf/gb_ndmp_get_info.nasl
    "1.3.6.1.4.1.25623.1.0.806530", # gb_opennms_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148575", # gb_graylog_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114037", # gb_hikvision_ip_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.125242", # gb_dotnetnuke_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148588", # gb_progress_ws_ftp_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148606", # gb_zimbra_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148615", # gb_openwrt_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148632", # gb_koha_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104315", # gb_xerox_docushare_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148684", # gsf/gb_7signal_sonar_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148716", # gsf/gb_avaya_contact_center_select_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148719", # gsf/gb_rstudio_connect_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148746", # gsf/gb_fortinet_fortiportal_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171189", # gsf/gb_fortinet_fortitester_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104358", # gsf/gb_fortinet_fortiproxy_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104763", # gsf/gb_fortinet_fortiddos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148932", # gsf/gb_vmware_workspace_one_assist_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148919", # gsf/gb_progress_datadirect_hybrid_data_pipeline_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149023", # gsf/gb_vmware_vrni_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.902480", # gb_timelive_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105387", # gb_open-xchange_ox_app_suite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149043", # gb_gunicorn_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149064", # gb_sonesix_conference_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149084", # gsf/gb_securepoint_utm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100681", # gb_teamspeak_server_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149392", # gsf/gb_connectwise_r1soft_sbm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149417", # gsf/gb_barracuda_cloudgen_wan_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170464", # gb_home_assistant_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103379", # gb_op5_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149584", # gsf/gb_checkmk_appliance_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149590", # gsf/gb_apache_superset_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149635", # gsf/gb_cpanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149727", # gsf/gb_moxa_mxsecurity_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.126424", # gb_ultidev_cassini_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149745", # gsf/gb_progress_moveit_transfer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100196", # gb_aas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153005", # gb_progress_whatsup_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104826", # gsf/gb_edgecore_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149845", # gsf/gb_fortra_globalscape_eft_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142120", # gb_sogo_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808648", # gb_apache_ambari_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105809", # gb_docker_http_rest_api_detect.nasl
    "1.3.6.1.4.1.25623.1.0.805661", # gb_adobe_connect_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104875", # gsf/gb_microsoft_skype_for_business_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150784", # gsf/gb_cloudpanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103923", # gb_wsman_winrm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104703", # gb_microsoft_msmq_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141450", # gb_redhat_openshift_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104927", # gsf/gb_jumpserver_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170668", # gb_tenable_nessus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.801102", # gb_adobe_robohelp_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153628", # gsf/gb_qlik_sense_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.124508", # gsf/gb_manageengine_m365_security_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170743", # gsf/gb_manageengine_endpoint_central_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170747", # gsf/gb_manageengine_endpoint_central_server_msp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100752", # gb_nagios_xi_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.900811", # gb_digium_asterisk_sip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114269", # gsf/gb_aveva_intouch_access_anywhere_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114281", # gsf/gb_aveva_plant_scada_access_anywhere_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151486", # gsf/gb_vinchin_backup_recovery_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100693", # gb_splunk_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151621", # gb_barracuda_web_application_firewall_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103612", # gb_symantec_messaging_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114368", # gb_rspamd_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114383", # gb_bitvise_ssh_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151684", # gsf/gb_cisco_expressway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151764", # gb_cisco_vcs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151744", # gsf/gb_adobe_framemaker_publishing_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151858", # gsf/gb_progress_openedge_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151870", # gsf/gb_aruba_clearpass_policy_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151885", # gsf/gb_arista_ng_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111080", # sw_tinyproxy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151898", # gsf/gb_devolutions_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151978", # gsf/gb_progress_telerik_report_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152021", # gsf/gb_progress_flowmon_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152019", # gsf/gb_vmware_sdwan_orchestrator_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152094", # gb_ibm_qradar_siem_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105304", # gb_f5_linerate_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105307", # gb_f5_linerate_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152135", # gsf/gb_dell_openmanage_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152161", # gsf/gb_recrystallize_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152179", # gsf/gb_kemp_ecs_connection_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152203", # gsf/gb_vmware_avi_load_balancer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.125109", # gsf/gb_veeam_service_provider_console_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152306", # gsf/gb_opentext_dimensions_rm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105162", # gb_f5_big_ip_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103241", # gsf/gb_zkbio_cvsecurity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809334", # gb_zkteco_zkbiosecurity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108000", # gb_collabora_libreoffice_online_http_detect.nasl
    # nb: Down here because while the product is usually installed on Linux Systems it is written in
    # PHP and thus there is a slight chance that it could have been installed on Windows as well.
    "1.3.6.1.4.1.25623.1.0.106035", # gb_froxlor_http_detect.nasl
    # Should be kept below as this seems to be running on e.g. Rocky Linux which is already detected
    # via e.g. gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.152310", # gsf/gb_fortinet_fortisiem_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152336", # gsf/gb_avideo_platform_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100889", # gb_freepbx_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152347", # gsf/gb_fortra_tripwire_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149858", # gsf/gb_veeam_backup_replication_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152398", # gsf/gb_pexip_infinity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140334", # gb_freeipa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152463", # gsf/gb_mailcow_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152533", # gb_dell_avamar_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152653", # gsf/gb_stormshield_sns_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152737", # gsf/gb_softing_edgeaggregator_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152753", # gsf/gb_softing_edgeconnector_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152807", # gb_ibm_storwize_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152871", # gsf/gb_ivanti_virtual_traffic_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152894", # gsf/gb_ada_web_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152897", # gsf/gb_mitel_mivoice_mx-one_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152901", # gsf/gb_openbmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152909", # gsf/gb_avaya_system_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152925", # gsf/gb_lg_simple_editor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106650", # gb_logsign_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152963", # gsf/gb_delta_electronics_diaenergie_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152987", # gsf/gb_versa_director_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105148", # gb_netiq_access_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.900348", # gb_cups_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141745", # gb_palo_alto_expedition_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152998", # gsf/gb_controlid_idsecure_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153203", # gsf/gb_watchguard_sso_agent_telnet_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153333", # gsf/gb_acronis_cyber_infrastructure_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153349", # gsf/gb_cyberpanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155121", # gsf/gb_dell_secure_connect_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153362", # gsf/gb_ibm_security_verify_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153381", # gsf/gb_apache_kylin_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153521", # gsf/gb_apache_hertzbeat_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153584", # gsf/gb_sailpoint_identityiq_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113117", # gb_kentico_cms_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153757", # gsf/gb_aviatrix_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153792", # gsf/gb_opentext_solutions_business_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153918", # gsf/gb_aruba_fabric_composer_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153972", # gsf/gb_wazuh_dashboard_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153985", # gsf/gb_audiocodes_ovoc_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153989", # gsf/gb_trimble_cityworks_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112030", # gb_apache_atlas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113968", # gsf/gb_beyondtrust_secure_remote_access_appliance_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105855", # gb_nuuo_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154107", # gsf/gb_beyondtrust_beyondinsight_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809483", # gb_apache_ranger_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140960", # gb_cyberark_password_vault_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103694", # gb_tandberg_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154168", # gsf/gb_hirsch_enterphone_mesh_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154174", # gsf/gb_veeam_backup_for_salesforce_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114991", # gsf/gb_mult_network_cameras_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171322", # gsf/gb_redhat_satellite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154266", # gsf/gb_apache_pinot_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154282", # gsf/gb_apache_answer_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107058", # gb_nagios_log_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.16338",  # mailman_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154376", # gb_postorius_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151761", # gsf/gb_connectwise_screenconnect_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154475", # gsf/gb_opnsense_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154497", # gsf/gb_opentext_advanced_authentication_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154539", # gsf/gb_seppmail_secure_email_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154542", # gsf/gb_versa_concerto_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154545", # gsf/gb_cisco_secure_networks_analytics_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154572", # gsf/gb_samsung_magicinfo_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154586", # gsf/gb_zkbio_time_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.127890", # gsf/gb_huawei_esight_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154594", # gsf/gb_mici_network_fax_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.125197", # gsf/gb_sunbird_dcim_dctrack_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171545", # gsf/gb_huawei_fusionsphere_cps_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141443", # gb_cisco_nfvis_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154653", # gb_infoblox_netmri_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154660", # gsf/gb_vmware_nsx_data_center_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.125213", # gsf/gb_huawei_fusionsphere_om_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154753", # gsf/gb_hpe_storeonce_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154773", # gsf/gb_zendto_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154792", # gsf/gb_sitecore_identity_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154840", # gsf/gb_netbox_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.133006", # gsf/gb_checkbox_survey_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154865", # gsf/gb_cisco_spaces_connector_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154908", # gb_puppet_enterprise_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154959", # gsf/gb_gfi_archiver_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155039", # gsf/gb_xorux_xormon_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155042", # gsf/gb_xorux_lpar2rrd_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155178", # gsf/gb_n-able_n-central_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155187", # gsf/gb_pandora_itsm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155211", # gsf/gb_securden_unified_pam_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155213", # gsf/gb_dell_cloudlink_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105799", # gb_cisco_ucs_platform_emulator_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155375", # gsf/gb_xorcom_completepbx_consolidation.nasl
    #  nb: Down here because an ADB service could be run on an Android emulator as well...
    "1.3.6.1.4.1.25623.1.0.108447", # gb_android_adb_detect.nasl
    "1.3.6.1.4.1.25623.1.0.10150",  # netbios_name_get.nasl
    # nb: The only difference to os_get_txt_txt_list() is that the list here is missing
    # gb_nmap_os_detection.nasl as this VT is (currently) not registering a CPE...
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
  );

  return oid_list;
}

# @brief Returns the list of OIDs of VTs doing text based OS detection. The list is sorted by
#        decreasing accuracy (best is first).
#
# @return The list of OIDs of VTs as described in the function description.
#
function os_get_txt_src_list() {

  local_var oid_list;

  oid_list = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810231", # gb_apple_macosx_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149245", # gsf/gb_vmware_esxi_openslp_udp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149705", # gsf/gb_vmware_esxi_openslp_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150826", # gsf/gb_vmware_sdwan_edge_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96206",  # gb_ssh_cisco_ios_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105544", # gb_cisco_cucmim_version.nasl
    "1.3.6.1.4.1.25623.1.0.147755", # gb_cisco_cucm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105690", # gb_cisco_nx_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105068", # gb_cyclades_detect.nasl
    # nb: The FortiGate VT should be before all other Fortinet VTs registering FortiOS because it is
    # currently registering the FortiOS version as well.
    "1.3.6.1.4.1.25623.1.0.147797", # gb_fortinet_fortigate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105313", # gb_fortinet_fortios_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144208", # gb_fortinet_fortimail_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149328", # gsf/gb_fortinet_fortiadc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149332", # gsf/gb_fortinet_fortinac_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171155", # gsf/gb_fortinet_fortiswitch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170963", # gb_fortinet_fortiweb_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114880", # gb_fortinet_fortimanager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171017", # gb_fortinet_fortianalyzer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105440", # gb_cisco_esa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105441", # gb_cisco_wsa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105433", # gb_cisco_csma_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105533", # gb_cisco_ip_phone_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105532", # gb_cisco_ios_xr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146071", # gsf/gb_cisco_sdwan_vedge_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149142", # gb_juniper_junos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153760", # gb_juniper_junos_space_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152516", # gsf/gb_juniper_ssr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105263", # gb_paloalto_panos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114574", # gsf/gb_f5_big-ip_next_central_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114597", # gsf/gb_f5_big-ip_next_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114573", # gsf/gb_f5_f5os_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142605", # gsf/gb_paloalto_globalprotect_portal_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105266", # gb_screenos_version.nasl
    "1.3.6.1.4.1.25623.1.0.151229", # gb_extremeos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152371", # gsf/gb_dell_emc_smartfabric_os10_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108566", # gb_tippingpoint_sms_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106513", # gb_cisco_asa_version_snmp.nasl
    "1.3.6.1.4.1.25623.1.0.105222", # gb_cisco_asa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105033", # gb_cisco_asa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153239", # gsf/gb_cisco_meraki_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105430", # gb_cisco_wlc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143118", # gb_f5_big_iq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104593", # gb_riello_ups_netman_204_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144335", # gsf/gb_secomea_gatemanager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106494", # gb_arista_eos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149143", # gsf/gb_barox_switch_snmp_detection.nasl
    "1.3.6.1.4.1.25623.1.0.151625", # gsf/gb_glinet_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149387", # gsf/gb_alcatel_omniswitch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153343", # gsf/gb_elvaco_cme_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108307", # gb_netgear_prosafe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141740", # gb_netgear_wnap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146185", # gb_netgear_smart_cloud_switch_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107228", # gb_netgear_dgn2200_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112334", # gb_netgear_dgnd3700_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141679", # gb_wd_mybook_live_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153820", # gb_kerio_control_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108311", # gb_hirschmann_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154741", # gsf/gb_abb_eibport_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140590", # gb_phoenix_fl_comserver_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149706", # gsf/gb_phoenixcontact_plc_device_pcworx_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154823", # gsf/gb_advantech_wise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153980", # gsf/gb_audiocodes_sbc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144115", # gb_geneko_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143245", # gsf/gb_unitronics_plc_pcom_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144128", # gb_option_cloudgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810608", # gb_mikrotik_router_routeros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.113169", # gb_gpon_home_router_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145096", # gsf/gb_zyxel_usg_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148200", # gsf/gb_zyxel_atp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148183", # gsf/gb_zyxel_vpn_firewall_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148210", # gsf/gb_zyxel_nxc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148242", # gsf/gb_zyxel_nap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148259", # gsf/gb_zyxel_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148282", # gsf/gb_zyxel_nwa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148349", # gsf/gb_zyxel_wac_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148397", # gsf/gb_zyxel_wax_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148479", # gsf/gb_zyxel_uag_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148721", # gb_zyxel_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153896", # gb_zyxel_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154134", # gsf/gb_ubiquiti_unifi_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.155109", # gsf/gb_ubiquiti_edgeswitch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140540", # gb_sitefinity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150750", # gsf/gb_contec_solarview_compact_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144354", # gb_zhone_znid_gpon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143523", # gsf/gb_aruba_switches_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149463", # gsf/gb_arrayos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141648", # gb_teltonika_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106833", # gb_garrettcom_switch_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103710", # gb_3com_officeconnect_vpn_firewall_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149276", # gb_hpe_officeconnect_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.155002", # gsf/gb_hpe_instant_on_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155011", # gsf/gb_hpe_instant_on_switch_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148296", # gsf/gb_hp_3com_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170300", # gb_axis_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105144", # gb_xenserver_version.nasl
    "1.3.6.1.4.1.25623.1.0.105659", # gb_cisco_ios_xe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144170", # gb_cisco_nam_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144402", # gb_cisco_small_business_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147593", # gb_cisco_small_business_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145983", # gsf/gb_cisco_hyperflex_data_platform_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117529", # gsf/gb_circontrol_circarlife_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117533", # gsf/gb_circontrol_raption_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147867", # gb_sophos_xg_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105155", # gb_mcafee_email_gateway_version.nasl
    "1.3.6.1.4.1.25623.1.0.140058", # gb_brocade_netiron_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108335", # gb_brocade_fabricos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105244", # gb_aruba_arubaos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146362", # gsf/gb_aruba_instant_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106864", # gb_sophos_cyberoam_utm_ngfw_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106875", # gb_aerohive_hiveos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103875", # gb_qnap_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170202", # gb_synology_dsm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170230", # gb_synology_srm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142078", # gb_drobo_nas_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140995", # gb_buffalo_airstation_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153874", # gb_unraid_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103753", # gb_seagate_blackarmor_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106840", # gb_terramaster_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112353", # gb_buffalo_nas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149001", # gb_seagate_central_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.805964", # gb_netsweeper_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811915", # gb_trendmicro_smart_protection_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149991", # gsf/gb_citrix_sharefile_storagezones_controller_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148299", # gsf/gb_citrix_adm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106151", # gb_barracuda_load_balancer_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149737", # gsf/gb_barracuda_email_security_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142729", # gsf/gb_fortinet_fortios_sslvpn_portal_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106096", # gb_siemens_simatic_s7_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140738", # gb_simatic_cp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145830", # gb_simatic_scalance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140811", # gb_siemens_ruggedcom_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151045", # gsf/gb_siemens_logo_plc_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142907", # gsf/gb_ewon_flexy_cosy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143136", # gsf/gb_optergy_proton_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144491", # gb_honeywell_xlweb_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146123", # gsf/gb_schneider_powerlogic_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152659", # gsf/gb_schneider_modicon_controller_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152727", # gsf/gb_schneider_powerlogic_protection_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142369", # gb_easyio_30p_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141019", # gb_sonos_upnp_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155013", # gb_sonos_device_airplay_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152044", # gsf/gb_inotec_cps_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.20285",  # ilo_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105176", # gb_ibm_gcm_kvm_webinterface_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147702", # gb_watchguard_firebox_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108338", # gb_vibnode_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108347", # gb_hyperip_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143323", # gb_ruckus_unleashed_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143341", # gsf/gb_ruckus_zonedirector_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148924", # gsf/gb_ruckus_virtual_smartzone_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148928", # gsf/gb_ruckus_smartzone_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149192", # gsf/gb_ruckus_smartcell_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103910", # gb_avm_fritz_box_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142677", # gb_avm_fritz_wlanrepeater_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143196", # gb_digitalisierungsbox_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143419", # gb_lancom_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143663", # gb_draytek_vigor_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103794", # gb_hp_onboard_administrator_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144339", # gb_cisco_ata_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106216", # gb_cisco_spa_voip_device_sip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113281", # gb_yealink_ip_phone_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151013", # gsf/gb_polycom_ipphone_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153565", # gsf/gb_poly_videoconference_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117074", # gb_dlink_dsr_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170325", # gb_dlink_dap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170779", # gb_dlink_dhp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171557", # gb_dlink_dsl_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106015", # gb_dlink_dns_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170244", # gb_dlink_dir_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171565", # gb_dlink_dwr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.171562", # gb_dlink_dcs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170280", # gsf/gb_dlink_dnh_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170349", # gsf/gb_dlink_generic_device_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107252", # gb_dgs_1500_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107300", # gb_trendnet_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811880", # gb_tp_link_routers_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171697", # gb_fxc_router_http_detect.nasl
    # nb: Needs to be after all D-Link detections above because this *might* only register an
    # unknown model while the others above could be more detailed...
    "1.3.6.1.4.1.25623.1.0.170206", # gsf/gb_dlink_devices_hnap_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170243", # gsf/gb_dlink_devices_upnp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170242", # gsf/gb_dlink_devices_mdns_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144526", # gb_linksys_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148591", # gb_arris_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108488", # gb_wd_mycloud_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152791", # gb_sangoma_sbc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108491", # gb_intelbras_ncloud_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141923", # gb_netapp_data_ontap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143673", # gb_emc_isilon_onefs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112339", # gb_brickcom_network_camera_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155078", # gb_ptzoptics_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142807", # gb_ricoh_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141736", # gb_ricoh_iwb_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142838", # gb_lexmark_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142901", # gb_toshiba_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141824", # gb_xerox_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170523", # gb_fujifilm_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112774", # gb_sato_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112777", # gsf/gb_konicaminolta_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146406", # gb_epson_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147494", # gb_canon_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147517", # gb_kyocera_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147610", # gb_hp_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149040", # gb_sharp_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170550", # gb_brother_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151376", # gb_dell_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108494", # gb_codesys_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106075", # gb_sierrawireless_acemanager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144306", # gsf/gb_nimbus_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.141684", # gb_simatic_hmi_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141766", # gb_wago_plc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145363", # gsf/gb_abb_ac500_opcua_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153384", # gsf/gb_abb_aspect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141772", # gb_rockwell_micrologix_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142010", # gb_rockwell_powermonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150832", # gsf/gb_rockwell_controllogix_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154027", # gsf/gb_rockwell_guardlogix_ethernetip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154155", # gsf/gb_liebert_crv_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142684", # gb_crestron_airmedia_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141365", # gb_crestron_cip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141174", # gb_crestron_ctp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147924", # gsf/gb_turck_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.113953", # gsf/gb_franklin_fueling_systems_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113942", # gsf/gb_siemens_sicam_a8000_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808203", # gb_sunny_webbox_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145200", # gb_loxone_miniserver_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114075", # gb_beward_ip_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114095", # gb_zavio_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114097", # gb_tp_link_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808237", # gb_edgecore_ES3526XA_manager_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114099", # gb_pearl_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114000", # gb_qsee_ip_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107335", # gb_vicon_industries_network_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105789", # gb_riverbed_steelcentral_version.nasl
    "1.3.6.1.4.1.25623.1.0.106845", # gb_riverbed_steelhead_ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106844", # gb_riverbed_steelhead_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143317", # gsf/gb_sonicwall_email_security_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143539", # gb_dell_sonicwall_sma_sra_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107120", # gb_sonicwall_ums_gms_analyzer_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146162", # gsf/gb_sonicwall_nsm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106569", # gb_dell_sonicwall_tz_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147864", # gsf/gb_sonicwall_ns_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151575", # gsf/gb_sonicwall_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141135", # gb_quest_kace_sma_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148118", # gb_quest_kace_sda_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143631", # gb_grandstream_ucm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143704", # gb_grandstream_gxp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153692", # gsf/gb_four_faith_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151042", # gb_moxa_edr_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143571", # gb_moxa_iologik_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143598", # gb_moxa_mgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145968", # gb_moxa_nport_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149646", # gb_moxa_miineport_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152565", # gsf/gb_moxa_oncell_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151835", # gb_netis_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151840", # gb_moxa_eds_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151362", # gb_apc_ups_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146507", # gsf/gb_ruijie_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150893", # gsf/gb_mitel_smb_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152413", # gsf/gb_mitel_ip_phones_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140631", # gb_cambium_cnpilot_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143395", # gsf/gb_honeywell_ip-ak2_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147410", # gsf/gb_auerswald_compact_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147412", # gsf/gb_auerswald_commander_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.147414", # gsf/gb_auerswald_comfortel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108940", # gsf/gb_spinetix_player_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108943", # gsf/gb_spinetix_fusion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145012", # gsf/gb_contiki_os_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145014", # gsf/gb_ethernut_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106196", # gb_westermo_weos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145072", # gsf/gb_ui_edgepower_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117491", # gsf/gb_maipu_network_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104990", # gsf/gb_honeywell_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117431", # gsf/gb_flir_ax8_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117449", # gsf/gb_flir_a3xx_series_consolidation.nasl
    # nb: Should be below other FLIR detections because we want to use the FLIR camera firmware
    # version as the OS version if possible.
    "1.3.6.1.4.1.25623.1.0.117452", # gsf/gb_flir_neco_platform_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170419", # gsf/gb_apsystems_energy_communication_unit_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112731", # gb_huawei_vrp_network_device_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152275", # gb_huawei_yunshan_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144459", # gb_huawei_ibmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.806636", # gb_huawei_VP9660_mcu_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146155", # gb_huawei_home_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.813817", # gb_avtech_avc7xx_dvr_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809066", # gb_avtech_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149912", # gsf/gb_ubiquiti_edgerouter_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.143355", # gb_huawei_euleros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105614", # gb_cisco_pis_version.nasl
    # nb: This needs to be after gather-package-list.nasl as that is registering the OS in more detail
    "1.3.6.1.4.1.25623.1.0.105522", # gb_cisco_firepower_management_center_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146019", # gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154849", # gb_cisco_ise_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152320", # gb_checkpoint_fw_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112309", # gb_nec_communication_platforms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142731", # gsf/gb_tibco_loglogic_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142733", # gsf/gb_inea_me-rtu_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108632", # gsf/gb_mult_vendors_wlan_controller_aps_detection.nasl
    "1.3.6.1.4.1.25623.1.0.142756", # gsf/gb_dell_emc_powerconnect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142875", # gsf/gb_silverpeak_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143256", # gb_inim_smartlan_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143512", # gsf/gb_timetools_ntp_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143657", # gsf/gb_beckhoff_ads_udp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112771", # gb_dsx_comm_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145540", # gsf/gb_vmware_view_planner_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145934", # gsf/gb_omnissa_workspace_one_uem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148610", # gsf/gb_vmware_hcx_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105862", # gb_vmware_vrealize_operations_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149235", # gb_vmware_vrealize_log_insight_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.111015", # sw_f5_firepass_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105303", # gb_f5_enterprise_manager_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104585", # gb_meinberg_lantime_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.119032", # gsf/gb_ericsson_mini-link_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105586", # gb_ssh_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106030", # gb_accellion_fta_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114106", # gsf/gb_synetica_datastream_devices_telnet_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142620", # gsf/gb_cisco_vision_dynamic_signage_director_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142850", # gsf/gb_cisco_ind_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117048", # gsf/gb_cisco_csm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147479", # gsf/gb_vmware_horizon_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143935", # gb_openvpn_access_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112450", # gb_cradlepoint_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107343", # gb_octopi_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.807073", # gb_sophos_utm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811655", # gb_technicolor_tc7200_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170268", # gb_ispy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170553", # gb_southrivertech_titan_ftp_server_consolidation.nasl
    # nb: The Proxmox and F5 Enterprise Manager VTs were put after gb_ssh_os_detection.nasl because
    # they might only report a generic Debian/CentOS CPE without including the version which would
    # overwrite the SSH one.
    "1.3.6.1.4.1.25623.1.0.117270", # gb_proxmox_ve_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105305", # gb_f5_enterprise_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113756", # gb_cisco_smi_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144350", # gb_pulse_connect_secure_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144140", # gsf/gb_ibm_spectrum_protect_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144152", # gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105271", # gb_citrix_netscaler_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810998", # gb_intel_standard_manageability_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144564", # gb_cisco_ucs_director_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144905", # gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104469", # gsf/gb_barracuda_cloudgen_firewall_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104596", # gsf/gb_barracuda_cloudgen_based_device_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144446", # gsf/gb_vxworks_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144573", # gsf/gb_mobileiron_sentry_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148730", # gsf/gb_cynet_360_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149596", # gb_mailenable_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149618", # gsf/gb_oracle_opera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149660", # gsf/gb_sophos_mobile_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151108", # gsf/gb_supermicro_bmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151265", # gsf/gb_veeam_one_consolidation.nasl
    # nb: The two F5 ones should be before gb_snmp_os_detection.nasl as that one is registering a
    # more generic Linux OS.
    "1.3.6.1.4.1.25623.1.0.105159", # gb_f5_big_ip_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114638", # gsf/gb_f5_big-ip_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108014", # gb_dns_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.105355", # gb_ftp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103979", # gb_ucs_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104498", # gb_cwp_consolidation.nasl
    # nb: Should be before sw_http_os_detection.nasl and gb_microsoft_iis_http_detect.nasl as the
    # devices are emulating an IIS banner which could cause false OS reporting.
    "1.3.6.1.4.1.25623.1.0.104949", # gsf/gb_sangfor_ngaf_http_detect.nasl
    # nb: Should be before sw_http_os_detection.nasl as it detects the Windows OS version in more
    # detail.
    "1.3.6.1.4.1.25623.1.0.900710", # gb_microsoft_iis_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111067", # sw_http_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.100970", # gsf/gb_viessmann_vitogate_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111068", # sw_mail_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111069", # sw_telnet_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108192", # gb_mysql_mariadb_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.100292", # gb_apcnisd_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140184", # gb_dahua_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114084", # gb_amcrest_ip_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108682", # gb_pptp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108590", # gb_ntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # mdns_service_detection.nasl
    "1.3.6.1.4.1.25623.1.0.10144",  # gb_microsoft_sql_server_tcp_ip_listener_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140000", # gb_apple_tv_version.nasl
    "1.3.6.1.4.1.25623.1.0.105899", # gb_apple_tv_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108200", # gb_upnp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108201", # gb_sip_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140096", # gb_checkmk_agent_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100062", # ms_rdp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143777", # gsf/gb_apache_activemq_jms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141106", # gb_schneider_ecostruxure_geo_scada_expert_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107788", # gsf/gb_trendmicro_apex_central_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.118034", # gsf/gb_clickstudios_passwordstate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141987", # gb_suremdm_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108044", # dcetest.nasl
    "1.3.6.1.4.1.25623.1.0.103081", # gb_fsecure_internet_gatekeeper_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.902058", # secpod_ocs_inventory_ng_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144370", # gsf/gb_symantec_endpoint_protection_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108284", # gb_hnap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108565", # gb_ident_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108342", # gb_pi-hole_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105569", # gb_citrix_xenmobile_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117275", # gb_dnsmasq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112869", # gb_dropbear_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141467", # gb_monit_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108451", # gb_rtsp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140337", # gb_netapp_storagegrid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105964", # gb_solarwinds_sam_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151935", # gsf/gb_solarwinds_sem_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151242", # gsf/gb_solarwinds_arm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108455", # gb_nntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106220", # gb_siemens_sinema_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143411", # gsf/gb_siemens_sppa-t3000_app_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105150", # gb_microsoft_exchange_outlook_web_app_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103825", # gb_openvas_manager_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103841", # gb_greenbone_gsa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144367", # gb_aerospike_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100870", # gb_artica_proxy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144839", # gsf/gb_ruckus_iot_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104433", # gsf/gb_bigbluebutton_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112850", # gsf/gb_observium_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145038", # gsf/gb_solarwinds_orion_platform_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145045", # gb_microfocus_filr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145210", # gsf/gb_cisco_dna_center_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146403", # gsf/gb_magicflow_msa_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145205", # gsf/gb_cisco_smart_software_manager_on_prem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145436", # gsf/gb_cisco_sdwan_vmanage_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145298", # gsf/gb_apache_druid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145329", # gb_altn_mdaemon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145380", # gsf/gb_netmotion_mobility_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145395", # gsf/gb_samsung_wlan_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145444", # gsf/gb_nexusdb_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145481", # gsf/gb_rzk_dolusoft_fortilogger_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145485", # gsf/gb_yealink_device_management_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145507", # gsf/gb_inspur_clusterengine_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112873", # gsf/gb_passbolt_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145601", # gsf/gb_netapp_cloud_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117269", # gb_elastix_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145782", # gsf/gb_vmware_workspace_one_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117421", # gsf/gb_kemp_loadmaster_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145924", # gsf/gb_voipmonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150930", # gsf/gb_ivanti_avalanche_consolidation.nasl
    # nb: The CSA one should be after gather-package-list.nasl as the appliance seems to run on CentOS
    "1.3.6.1.4.1.25623.1.0.153131", # gsf/gb_ivanti_cloud_services_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.150958", # gsf/gb_ivanti_epm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151970", # gsf/gb_ivanti_neurons_for_itsm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145946", # gsf/gb_blackberry_uem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142006", # gb_solarwinds_orion_npm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146034", # gb_gate_one_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146046", # gsf/gb_tg8_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146106", # gsf/gb_akkadian_provisioning_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146249", # gsf/gb_dell_wyse_management_suite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106738", # gb_kaseya_vsa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146284", # gsf/gb_philips_vue_pacs_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146322", # gsf/gb_philips_vue_motion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146387", # gsf/gb_elastic_cloud_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146413", # gsf/gb_aapanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146649", # gsf/gb_cisco_firepower_device_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141122", # gb_manageengine_adaudit_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146718", # gsf/gb_manageengine_adselfservice_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146787", # gb_manageengine_admanager_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.149108", # gsf/gb_manageengine_ad360_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149111", # gsf/gb_manageengine_endpoint_dlp_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149140", # gsf/gb_manageengine_patch_manager_plus_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141285", # gb_manageengine_exchange_reporter_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146813", # gsf/gb_fatpipe_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140134", # gb_dell_powerscale_insightiq_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146867", # gsf/gb_cisco_intersight_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170134", # gsf/gb_cisco_nexus_dashboard_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.801223", # gb_weborf_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170049", # gb_gitlab_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141670", # gb_veritas_netbackup_appliance_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108191", # gb_sitecore_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117951", # gb_lmtp_service_detect.nasl
    "1.3.6.1.4.1.25623.1.0.125001", # gb_moxa_mxview_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105931", # gb_bmc_trackit_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100405", # gb_zabbix_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.147697", # gb_vmware_nsx_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114022", # gb_sony_network_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140809", # gsf/gb_ndmp_get_info.nasl
    "1.3.6.1.4.1.25623.1.0.806530", # gb_opennms_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148575", # gb_graylog_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114037", # gb_hikvision_ip_camera_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.125242", # gb_dotnetnuke_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148588", # gb_progress_ws_ftp_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148606", # gb_zimbra_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148615", # gb_openwrt_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148632", # gb_koha_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104315", # gb_xerox_docushare_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148684", # gsf/gb_7signal_sonar_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148716", # gsf/gb_avaya_contact_center_select_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148719", # gsf/gb_rstudio_connect_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148746", # gsf/gb_fortinet_fortiportal_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171189", # gsf/gb_fortinet_fortitester_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104358", # gsf/gb_fortinet_fortiproxy_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104763", # gsf/gb_fortinet_fortiddos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.148932", # gsf/gb_vmware_workspace_one_assist_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.148919", # gsf/gb_progress_datadirect_hybrid_data_pipeline_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149023", # gsf/gb_vmware_vrni_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.902480", # gb_timelive_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105387", # gb_open-xchange_ox_app_suite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149043", # gb_gunicorn_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149064", # gb_sonesix_conference_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149084", # gsf/gb_securepoint_utm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100681", # gb_teamspeak_server_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149392", # gsf/gb_connectwise_r1soft_sbm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149417", # gsf/gb_barracuda_cloudgen_wan_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170464", # gb_home_assistant_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103379", # gb_op5_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149584", # gsf/gb_checkmk_appliance_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149590", # gsf/gb_apache_superset_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149635", # gsf/gb_cpanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149727", # gsf/gb_moxa_mxsecurity_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.126424", # gb_ultidev_cassini_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149745", # gsf/gb_progress_moveit_transfer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100196", # gb_aas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153005", # gb_progress_whatsup_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.104826", # gsf/gb_edgecore_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149845", # gsf/gb_fortra_globalscape_eft_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142120", # gb_sogo_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808648", # gb_apache_ambari_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105809", # gb_docker_http_rest_api_detect.nasl
    "1.3.6.1.4.1.25623.1.0.805661", # gb_adobe_connect_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104875", # gsf/gb_microsoft_skype_for_business_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.150784", # gsf/gb_cloudpanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103923", # gb_wsman_winrm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104703", # gb_microsoft_msmq_tcp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141450", # gb_redhat_openshift_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104927", # gsf/gb_jumpserver_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.170668", # gb_tenable_nessus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.801102", # gb_adobe_robohelp_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153628", # gsf/gb_qlik_sense_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.124508", # gsf/gb_manageengine_m365_security_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170743", # gsf/gb_manageengine_endpoint_central_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.170747", # gsf/gb_manageengine_endpoint_central_server_msp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100752", # gb_nagios_xi_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.900811", # gb_digium_asterisk_sip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114269", # gsf/gb_aveva_intouch_access_anywhere_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114281", # gsf/gb_aveva_plant_scada_access_anywhere_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151486", # gsf/gb_vinchin_backup_recovery_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100693", # gb_splunk_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151621", # gb_barracuda_web_application_firewall_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103612", # gb_symantec_messaging_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114368", # gb_rspamd_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114383", # gb_bitvise_ssh_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151684", # gsf/gb_cisco_expressway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151764", # gb_cisco_vcs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151744", # gsf/gb_adobe_framemaker_publishing_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151858", # gsf/gb_progress_openedge_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151870", # gsf/gb_aruba_clearpass_policy_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.151885", # gsf/gb_arista_ng_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111080", # sw_tinyproxy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151898", # gsf/gb_devolutions_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151978", # gsf/gb_progress_telerik_report_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152021", # gsf/gb_progress_flowmon_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152019", # gsf/gb_vmware_sdwan_orchestrator_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152094", # gb_ibm_qradar_siem_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105304", # gb_f5_linerate_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105307", # gb_f5_linerate_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152135", # gsf/gb_dell_openmanage_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152161", # gsf/gb_recrystallize_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152179", # gsf/gb_kemp_ecs_connection_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152203", # gsf/gb_vmware_avi_load_balancer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.125109", # gsf/gb_veeam_service_provider_console_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152306", # gsf/gb_opentext_dimensions_rm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105162", # gb_f5_big_ip_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103241", # gsf/gb_zkbio_cvsecurity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809334", # gb_zkteco_zkbiosecurity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108000", # gb_collabora_libreoffice_online_http_detect.nasl
    # nb: Down here because while the product is usually installed on Linux Systems it is written in
    # PHP and thus there is a slight chance that it could have been installed on Windows as well.
    "1.3.6.1.4.1.25623.1.0.106035", # gb_froxlor_http_detect.nasl
    # Should be kept below as this seems to be running on e.g. Rocky Linux which is already detected
    # via e.g. gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.152310", # gsf/gb_fortinet_fortisiem_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152336", # gsf/gb_avideo_platform_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100889", # gb_freepbx_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152347", # gsf/gb_fortra_tripwire_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.149858", # gsf/gb_veeam_backup_replication_server_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152398", # gsf/gb_pexip_infinity_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140334", # gb_freeipa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152463", # gsf/gb_mailcow_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152533", # gb_dell_avamar_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152653", # gsf/gb_stormshield_sns_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152737", # gsf/gb_softing_edgeaggregator_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152753", # gsf/gb_softing_edgeconnector_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152807", # gb_ibm_storwize_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152871", # gsf/gb_ivanti_virtual_traffic_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152894", # gsf/gb_ada_web_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152897", # gsf/gb_mitel_mivoice_mx-one_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152901", # gsf/gb_openbmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152909", # gsf/gb_avaya_system_manager_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152925", # gsf/gb_lg_simple_editor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106650", # gb_logsign_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152963", # gsf/gb_delta_electronics_diaenergie_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.152987", # gsf/gb_versa_director_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105148", # gb_netiq_access_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.900348", # gb_cups_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141745", # gb_palo_alto_expedition_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.152998", # gsf/gb_controlid_idsecure_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153203", # gsf/gb_watchguard_sso_agent_telnet_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153333", # gsf/gb_acronis_cyber_infrastructure_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153349", # gsf/gb_cyberpanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155121", # gsf/gb_dell_secure_connect_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.153362", # gsf/gb_ibm_security_verify_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153381", # gsf/gb_apache_kylin_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153521", # gsf/gb_apache_hertzbeat_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153584", # gsf/gb_sailpoint_identityiq_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113117", # gb_kentico_cms_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153757", # gsf/gb_aviatrix_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153792", # gsf/gb_opentext_solutions_business_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153918", # gsf/gb_aruba_fabric_composer_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153972", # gsf/gb_wazuh_dashboard_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153985", # gsf/gb_audiocodes_ovoc_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.153989", # gsf/gb_trimble_cityworks_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112030", # gb_apache_atlas_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113968", # gsf/gb_beyondtrust_secure_remote_access_appliance_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105855", # gb_nuuo_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154107", # gsf/gb_beyondtrust_beyondinsight_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809483", # gb_apache_ranger_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140960", # gb_cyberark_password_vault_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103694", # gb_tandberg_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154168", # gsf/gb_hirsch_enterphone_mesh_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154174", # gsf/gb_veeam_backup_for_salesforce_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114991", # gsf/gb_mult_network_cameras_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171322", # gsf/gb_redhat_satellite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154266", # gsf/gb_apache_pinot_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154282", # gsf/gb_apache_answer_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107058", # gb_nagios_log_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.16338",  # mailman_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154376", # gb_postorius_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.151761", # gsf/gb_connectwise_screenconnect_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154475", # gsf/gb_opnsense_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154497", # gsf/gb_opentext_advanced_authentication_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154539", # gsf/gb_seppmail_secure_email_gateway_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154542", # gsf/gb_versa_concerto_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154545", # gsf/gb_cisco_secure_networks_analytics_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154572", # gsf/gb_samsung_magicinfo_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154586", # gsf/gb_zkbio_time_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.127890", # gsf/gb_huawei_esight_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154594", # gsf/gb_mici_network_fax_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.125197", # gsf/gb_sunbird_dcim_dctrack_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.171545", # gsf/gb_huawei_fusionsphere_cps_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141443", # gb_cisco_nfvis_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154653", # gb_infoblox_netmri_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154660", # gsf/gb_vmware_nsx_data_center_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.125213", # gsf/gb_huawei_fusionsphere_om_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154753", # gsf/gb_hpe_storeonce_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154773", # gsf/gb_zendto_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154792", # gsf/gb_sitecore_identity_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154840", # gsf/gb_netbox_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.133006", # gsf/gb_checkbox_survey_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.154865", # gsf/gb_cisco_spaces_connector_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154908", # gb_puppet_enterprise_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.154959", # gsf/gb_gfi_archiver_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155039", # gsf/gb_xorux_xormon_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155042", # gsf/gb_xorux_lpar2rrd_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155178", # gsf/gb_n-able_n-central_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155187", # gsf/gb_pandora_itsm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155211", # gsf/gb_securden_unified_pam_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155213", # gsf/gb_dell_cloudlink_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105799", # gb_cisco_ucs_platform_emulator_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.155375", # gsf/gb_xorcom_completepbx_consolidation.nasl
    # nb: Down here because an ADB service could be run on an Android emulator as well...
    "1.3.6.1.4.1.25623.1.0.108447", # gb_android_adb_detect.nasl
    "1.3.6.1.4.1.25623.1.0.10150",  # netbios_name_get.nasl
    # nb: This should be the only difference to os_get_txt_cpe_list() as this VT is (currently) not registering a CPE...
    "1.3.6.1.4.1.25623.1.0.108021", # gb_nmap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
  );

  return oid_list;
}
