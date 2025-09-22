# SPDX-FileCopyrightText: 2005 Michel Arboi
# SPDX-FileCopyrightText: New / improved code since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11154");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Collect banner of unknown services");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  # IMPORTANT: Don't add telnet.nasl or os_detection.nasl in here which have (indirect-)
  # dependencies to this VT. Adding this dependency would cause a dependency cycle...
  script_dependencies("apache_SSL_complain.nasl",
                      "gb_apcnisd_detect.nasl", "asip-status.nasl",
                      "auth_enabled.nasl",
                      "bugbear.nasl", "check_point_fw1_secureremote_detect.nasl",
                      "cheopsNG_detect.nasl", "cifs445.nasl",
                      "distcc_detection.nasl", "dns_server_tcp.nasl",
                      "dont_print_on_printers.nasl", "echo.nasl",
                      "ePo_detect.nasl", "find_service_spontaneous.nasl",
                      "famd_detect.nasl", "find_service6.nasl",
                      "gb_ab_ethernet_detect.nasl", "gb_aerospike_telnet_detect.nasl",
                      "gb_aerospike_xdr_detect.nasl", "gb_amqp_detect.nasl",
                      "gb_android_adb_detect.nasl", "gb_apache_cassandra_thrift_detect.nasl",
                      "gb_apache_jserv_ajp_detect.nasl", "gb_apache_zookeeper_tcp_detect.nasl",
                      "gb_arkeia_virtual_appliance_detect_617.nasl", "gb_veritas_backup_exec_remote_agent_ndmp_detect.nasl",
                      "gb_checkmk_agent_detect.nasl", "gb_chargen_detect_tcp.nasl",
                      "gb_cisco_smi_tcp_detect.nasl",
                      "gb_codesys_tcp_detect.nasl", "gb_crestron_cip_detect.nasl",
                      "gb_dnp3_detect.nasl", "gb_dont_scan_fragile_device.nasl",
                      "gb_emc_networker_portmapper_detect.nasl", "gb_epmd_detect.nasl",
                      "gb_ethernetip_tcp_detect.nasl",
                      "gb_fins_tcp_detect.nasl", "gb_freeswitch_mod_event_socket_service_detect.nasl",
                      "gb_hid_vertx_discoveryd_detect.nasl", "gb_ibm_db2_das_detect.nasl",
                      "gb_ibm_soliddb_detect.nasl", "gb_ibm_websphere_mq_mqi_detect.nasl",
                      "gb_informix_detect.nasl", "gb_jdwp_tcp_detect.nasl", "gb_kerberos_detect.nasl",
                      "gb_lantronix_mgm_tcp_detect.nasl", "gb_logitech_media_server_tcp_detect.nasl",
                      "gb_memcachedb_detect.nasl",
                      "gb_memcached_detect.nasl", "gb_modbus_detect.nasl",
                      "gb_mongodb_detect.nasl", "gb_mqtt_detect.nasl",
                      "gb_ndmp_detect.nasl",
                      "gb_netware_core_protocol_detect.nasl", "gb_niagara_fox_detect.nasl",
                      "gb_opc_ua_tcp_detect.nasl", "gb_openvas_administrator_detect.nasl",
                      "gb_openvas_manager_detect.nasl", "gb_openvpn_detect.nasl",
                      "gb_ossec-authd_detect.nasl", "gb_visionsoft_audit_detect.nasl",
                      "gb_pcworx_tcp_detect.nasl", "gb_proconos_tcp_detect.nasl",
                      "gb_qotd_detect_tcp.nasl", "gb_redis_detect.nasl",
                      "gb_riak_detect.nasl", "gb_rlogin_detect.nasl",
                      "gb_rmi_registry_detect.nasl", "gb_sap_maxdb_detect.nasl",
                      "gb_sap_router_detect.nasl", "gb_sap_msg_service_detect.nasl",
                      "gb_sap_diag_service_detect.nasl", "gb_siemens_simatic_s7_cotp_detect.nasl",
                      "gb_sybase_tcp_listen_detect.nasl", "gb_symantec_pcanywhere_access_server_detect.nasl",
                      "gb_teamspeak_server_tcp_detect.nasl", "gb_winbox_detect.nasl",
                      "gb_wsman_winrm_http_detect.nasl",
                      "gnutella_detect.nasl", "healthd_detect.nasl",
                      "hp_data_protector_installed.nasl", "ircd.nasl",
                      "ingres_db_detect.nasl",
                      "kerio_firewall_admin_port.nasl", "kerio_mailserver_admin_port.nasl",
                      "kerio_winroute_admin_port.nasl", "landesk_detect.nasl",
                      "lcdproc_detect.nasl", "ldap_detect.nasl",
                      "ms_rdp_detect.nasl", "gb_microsoft_sql_server_tcp_ip_listener_detect.nasl",
                      "gb_mysql_mariadb_remote_detect.nasl", "nagios_statd_detect.nasl",
                      "napster_detect.nasl",
                      "nessus_detect.nasl", "nntpserver_detect.nasl",
                      "ntp_open.nasl", "oracle_tnslsnr_version.nasl",
                      "ossim_server_detect.nasl", "PC_anywhere_tcp.nasl",
                      "perforce_detect.nasl", "gb_pcl_pjl_detect.nasl",
                      "gb_postgresql_tcp_detect.nasl",
                      "pptp_detect.nasl", "qmtp_detect.nasl",
                      "radmin_detect.nasl", "filemaker_tcp_detect.nasl",
                      "firebird_detect.nasl", "rexecd.nasl", "rpcinfo.nasl",
                      "rsh.nasl", "rtsp_detect.nasl", "gb_rsync_remote_detect.nasl",
                      "gb_rpc_portmap_tcp_detect.nasl", "shn_discard_tcp_detect.nasl",
                      "sip_detection_tcp.nasl", "socks.nasl",
                      "ssh_detect.nasl", "swat_detect.nasl", "sw_jenkins_http_detect.nasl",
                      "sw_netstat_service_detect.nasl", "sw_obby_detect.nasl",
                      "sw_policyd-weight_detect.nasl", "sw_sphinxsearch_detect.nasl",
                      "telnet.nasl", "gb_jenkins_cli_tcp_detect.nasl",
                      "vmware_server_detect.nasl", "vnc.nasl",
                      "vnc_security_types.nasl", "xmpp_detect.nasl",
                      "X.nasl", "xtel_detect.nasl",
                      "xtelw_detect.nasl", "yahoo_msg_running.nasl",
                      "zabbix_detect.nasl", "gb_slp_tcp_detect.nasl");

  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sap_gateway_detect.nasl", "gsf/gb_atg_service_detect.nasl",
                        "gsf/gb_dicom_service_detection.nasl", "gsf/gb_hp_imc_dbman_detect.nasl",
                        "gsf/gb_pcom_detect.nasl", "gsf/gb_drda_detect.nasl", "gsf/gb_iec_104_detect.nasl",
                        "gsf/gb_melsec_tcp_detect.nasl", "gsf/gb_stomp_detect.nasl",
                        "gsf/gb_oracle_t3_detect.nasl", "gsf/gb_zeromq_detect.nasl",
                        "gsf/gb_nimbus_detect.nasl", "gsf/gb_sage_adxadmin_detect.nasl",
                        "gsf/gb_juniper_junos_junoscript_detect.nasl",
                        "gsf/gb_vmware_vrealize_log_insight_thrift_detect.nasl",
                        "gsf/gb_rocket_unidata_universe_unirpc_detect.nasl",
                        "gsf/gb_iec_60870_5_104_detect.nasl",
                        "gsf/gb_apache_rocketmq_broker_detect.nasl",
                        "gsf/gb_apache_rocketmq_nameserver_detect.nasl",
                        "gsf/gb_redlion_crimson_service_tcp_detect.nasl",
                        "gsf/gb_anydesk_tcp_detect.nasl",
                        "gsf/gb_tacacs_tcp_detect.nasl",
                        "gsf/gb_fortinet_fortisiem_phmonitor_detect.nasl",
                        "gsf/gb_delta_electronics_diaenergie_cebc_detect.nasl");

  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin collect the banner from unknown/unidentified services.

  The actual reporting takes place in the separate VT 'Unknown OS and Service Banner Reporting'
  OID: 1.3.6.1.4.1.25623.1.0.108441.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("port_service_func.inc");
include("string_hex_func.inc");

port = get_kb_item( "Services/unknown" );
if( ! port )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( port == 139 )
  exit( 0 ); # Avoid silly messages

if( ! service_is_unknown( port:port ) )
  exit( 0 );

banner = unknown_banner_report( port:port );
if( ! banner )
  exit( 0 );

if( strlen( banner[1] ) >= 3 ) {

  set_kb_item( name:"unknown_os_or_service/available", value:TRUE ); # Used in gb_unknown_os_service_reporting.nasl

  if( "Hex" >< banner[0] )
    hexbanner = hexdump( ddata:hex2raw( s:banner[1] ) );
  else
    hexbanner = hexdump( ddata:banner[1] );

  report = 'Method: ' + banner[0] + '\n\n' + hexbanner;
  set_kb_item( name:"unknown_service_report/unknown_banner/" + port + "/report", value:report );
}

exit( 0 );
