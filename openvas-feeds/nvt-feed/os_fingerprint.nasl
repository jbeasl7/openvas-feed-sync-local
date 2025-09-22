# SPDX-FileCopyrightText: 2009 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102002");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-05-19 12:05:50 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (ICMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Product detection");
  script_dependencies("gb_greenbone_os_consolidation.nasl",
                      "gb_apple_mobile_detect.nasl", "gb_apple_macosx_server_detect.nasl",
                      "gb_vmware_esx_web_detect.nasl", "gb_vmware_esx_snmp_detect.nasl",
                      "gb_ssh_cisco_ios_get_version.nasl", "gb_cisco_cucmim_version.nasl",
                      "gb_cisco_cucm_consolidation.nasl", "gb_cisco_nx_os_consolidation.nasl",
                      "gb_cisco_ise_consolidation.nasl",
                      "gb_cyclades_detect.nasl", "gb_fortinet_fortios_http_detect.nasl",
                      "gb_fortinet_fortimail_consolidation.nasl", "gb_fortinet_fortigate_consolidation.nasl",
                      "gb_cisco_esa_version.nasl", "gb_cisco_wsa_version.nasl",
                      "gb_cisco_csma_consolidation.nasl", "gb_cisco_ip_phone_detect.nasl",
                      "gb_cisco_ios_xr_consolidation.nasl", "gb_juniper_junos_consolidation.nasl",
                      "gb_juniper_junos_space_consolidation.nasl",
                      "gb_paloalto_panos_consolidation.nasl", "gb_screenos_version.nasl",
                      "gb_extremeos_consolidation.nasl", "gb_tippingpoint_sms_consolidation.nasl",
                      "gb_cisco_asa_version_snmp.nasl", "gb_cisco_asa_version.nasl",
                      "gb_cisco_asa_http_detect.nasl", "gb_cisco_wlc_consolidation.nasl",
                      "gb_f5_big_iq_consolidation.nasl", "gb_riello_ups_netman_204_consolidation.nasl",
                      "gb_arista_eos_snmp_detect.nasl", "gb_netgear_prosafe_consolidation.nasl",
                      "gb_netgear_wnap_consolidation.nasl", "gb_netgear_smart_cloud_switch_http_detect.nasl",
                      "gb_netgear_dgn2200_http_detect.nasl", "gb_netgear_dgnd3700_http_detect.nasl",
                      "gb_wd_mybook_live_http_detect.nasl", "gb_kerio_control_consolidation.nasl",
                      "gb_hirschmann_consolidation.nasl", "gb_phoenix_fl_comserver_web_detect.nasl",
                      "gb_geneko_router_consolidation.nasl",
                      "gb_option_cloudgate_consolidation.nasl", "gb_mikrotik_router_routeros_consolidation.nasl",
                      "gb_gpon_home_router_detect.nasl", "gb_zhone_znid_gpon_consolidation.nasl",
                      "gb_teltonika_router_http_detect.nasl", "gb_garrettcom_switch_detect.nasl",
                      "gb_3com_officeconnect_vpn_firewall_detect.nasl", "gb_hpe_officeconnect_switch_consolidation.nasl",
                      "gb_axis_devices_consolidation.nasl",
                      "gb_xenserver_version.nasl", "gb_cisco_ios_xe_consolidation.nasl",
                      "gb_cisco_nam_consolidation.nasl", "gb_cisco_small_business_switch_consolidation.nasl",
                      "gb_sophos_xg_consolidation.nasl",
                      "gb_mcafee_email_gateway_version.nasl", "gb_brocade_netiron_snmp_detect.nasl",
                      "gb_brocade_fabricos_consolidation.nasl",
                      "gb_aruba_arubaos_snmp_detect.nasl", "gb_sophos_cyberoam_utm_ngfw_http_detect.nasl",
                      "gb_aerohive_hiveos_detect.nasl", "gb_qnap_nas_http_detect.nasl",
                      "gb_synology_dsm_consolidation.nasl", "gb_synology_srm_consolidation.nasl",
                      "gb_drobo_nas_consolidation.nasl", "gb_buffalo_airstation_detect.nasl",
                      "gb_unraid_consolidation.nasl", "gb_seagate_blackarmor_nas_detect.nasl",
                      "gb_terramaster_nas_http_detect.nasl", "gb_buffalo_nas_http_detect.nasl",
                      "gb_seagate_central_http_detect.nasl", "gb_netsweeper_http_detect.nasl",
                      "gb_trendmicro_smart_protection_server_detect.nasl",
                      "gb_barracuda_load_balancer_detect.nasl", "gb_siemens_simatic_s7_consolidation.nasl",
                      "gb_simatic_cp_consolidation.nasl", "gb_simatic_scalance_consolidation.nasl",
                      "gb_siemens_ruggedcom_consolidation.nasl", "gb_honeywell_xlweb_consolidation.nasl",
                      "gb_easyio_30p_http_detect.nasl", "gb_sonos_upnp_tcp_detect.nasl",
                      "gb_sonos_device_airplay_detect.nasl",
                      "ilo_detect.nasl", "gb_ibm_gcm_kvm_webinterface_detect.nasl",
                      "gb_watchguard_firebox_consolidation.nasl", "gb_vibnode_consolidation.nasl",
                      "gb_hyperip_consolidation.nasl", "gb_ruckus_unleashed_http_detect.nasl",
                      "gb_avm_fritz_box_consolidation.nasl", "gb_avm_fritz_wlanrepeater_consolidation.nasl",
                      "gb_digitalisierungsbox_consolidation.nasl", "gb_lancom_devices_consolidation.nasl",
                      "gb_draytek_vigor_consolidation.nasl", "gb_hp_onboard_administrator_detect.nasl",
                      "gb_cisco_ata_consolidation.nasl", "gb_cisco_spa_voip_device_sip_detect.nasl",
                      "gb_yealink_ip_phone_consolidation.nasl", "gb_dlink_dsr_http_detect.nasl",
                      "gb_dlink_dap_consolidation.nasl", "gb_dlink_dhp_consolidation.nasl",
                      "gb_dlink_dsl_consolidation.nasl", "gb_tp_link_routers_http_detect.nasl",
                      "gb_dlink_dns_http_detect.nasl", "gb_dlink_dir_consolidation.nasl",
                      "gb_dlink_dwr_consolidation.nasl", "gb_dlink_dcs_consolidation.nasl",
                      "gb_dgs_1500_detect.nasl", "gb_trendnet_router_http_detect.nasl",
                      "gb_fxc_router_http_detect.nasl",
                      "gb_linksys_devices_consolidation.nasl", "gb_arris_router_http_detect.nasl",
                      "gb_wd_mycloud_consolidation.nasl", "gb_sangoma_sbc_consolidation.nasl",
                      "gb_intelbras_ncloud_devices_http_detect.nasl", "gb_netapp_data_ontap_consolidation.nasl",
                      "gb_emc_isilon_onefs_consolidation.nasl", "gb_brickcom_network_camera_detect.nasl",
                      "gb_ptzoptics_camera_http_detect.nasl",
                      "gb_ricoh_printer_consolidation.nasl", "gb_ricoh_iwb_detect.nasl",
                      "gb_lexmark_printer_consolidation.nasl", "gb_toshiba_printer_consolidation.nasl",
                      "gb_xerox_printer_consolidation.nasl", "gb_sato_printer_consolidation.nasl",
                      "gb_epson_printer_consolidation.nasl", "gb_canon_printer_consolidation.nasl",
                      "gb_kyocera_printer_consolidation.nasl", "gb_hp_printer_consolidation.nasl",
                      "gb_fujifilm_printer_consolidation.nasl", "gb_brother_printer_consolidation.nasl",
                      "gb_sharp_printer_consolidation.nasl", "gb_dell_printer_consolidation.nasl",
                      "gb_codesys_os_detection.nasl", "gb_sierrawireless_acemanager_http_detect.nasl",
                      "gb_simatic_hmi_consolidation.nasl", "gb_wago_plc_consolidation.nasl",
                      "gb_rockwell_micrologix_consolidation.nasl", "gb_rockwell_powermonitor_http_detect.nasl",
                      "gb_crestron_airmedia_consolidation.nasl",
                      "gb_crestron_cip_detect.nasl", "gb_crestron_ctp_detect.nasl",
                      "gb_sunny_webbox_remote_detect.nasl", "gb_loxone_miniserver_consolidation.nasl",
                      "gb_beward_ip_camera_consolidation.nasl", "gb_zavio_ip_cameras_detect.nasl",
                      "gb_tp_link_ip_cameras_detect.nasl", "gb_edgecore_ES3526XA_manager_remote_detect.nasl",
                      "gb_pearl_ip_cameras_detect.nasl",
                      "gb_qsee_ip_camera_http_detect.nasl", "gb_vicon_industries_network_camera_consolidation.nasl",
                      "gb_riverbed_steelcentral_version.nasl", "gb_riverbed_steelhead_ssh_detect.nasl",
                      "gb_riverbed_steelhead_http_detect.nasl", "gb_dell_sonicwall_sma_sra_consolidation.nasl",
                      "gb_sonicwall_ums_gms_analyzer_http_detect.nasl",
                      "gb_dell_sonicwall_tz_snmp_detect.nasl",
                      "gb_quest_kace_sma_http_detect.nasl", "gb_quest_kace_sda_http_detect.nasl",
                      "gb_grandstream_ucm_consolidation.nasl", "gb_grandstream_gxp_consolidation.nasl",
                      "gb_moxa_edr_devices_consolidation.nasl", "gb_moxa_iologik_devices_consolidation.nasl",
                      "gb_moxa_mgate_consolidation.nasl", "gb_moxa_nport_consolidation.nasl",
                      "gb_moxa_miineport_consolidation.nasl", "gb_netis_router_consolidation.nasl",
                      "gb_moxa_eds_consolidation.nasl", "gb_apc_ups_consolidation.nasl",
                      "gb_cambium_cnpilot_consolidation.nasl", "gb_westermo_weos_snmp_detect.nasl",
                      "gb_windows_cpe_detect.nasl", "gb_huawei_ibmc_consolidation.nasl",
                      "gb_huawei_VP9660_mcu_detect.nasl", "gb_huawei_home_gateway_http_detect.nasl",
                      "gb_avtech_avc7xx_dvr_device_detect.nasl", "gb_avtech_device_detect.nasl",
                      "gather-package-list.nasl", "gb_huawei_euleros_consolidation.nasl",
                      "gb_cisco_pis_version.nasl", "gb_cisco_firepower_management_center_consolidation.nasl",
                      "gb_checkpoint_fw_consolidation.nasl", "gb_smb_windows_detect.nasl",
                      "gb_nec_communication_platforms_detect.nasl", "gb_inim_smartlan_consolidation.nasl",
                      "gb_dsx_comm_devices_detect.nasl", "gb_vmware_vrealize_operations_manager_http_detect.nasl",
                      "gb_vmware_vrealize_log_insight_consolidation.nasl", "gb_meinberg_lantime_consolidation.nasl",
                      "gb_ssh_os_detection.nasl", "gb_openvpn_access_server_consolidation.nasl",
                      "gb_cradlepoint_router_consolidation.nasl", "gb_octopi_http_detect.nasl",
                      "gb_sophos_utm_http_detect.nasl", "gb_technicolor_tc7200_snmp_detect.nasl",
                      "gb_ispy_http_detect.nasl",
                      "gb_accellion_fta_detect.nasl", "gb_proxmox_ve_consolidation.nasl",
                      "gb_cisco_smi_tcp_detect.nasl", "gb_pulse_connect_secure_consolidation.nasl",
                      "gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl",
                      "gb_citrix_netscaler_consolidation.nasl", "gb_intel_standard_manageability_detect.nasl",
                      "gb_cisco_ucs_director_consolidation.nasl", "gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl",
                      "gb_huawei_vrp_network_device_consolidation.nasl",
                      "gb_huawei_yunshan_os_consolidation.nasl", "gb_snmp_os_detection.nasl",
                      "gb_dns_os_detection.nasl", "gb_ftp_os_detection.nasl",
                      "smb_nativelanman.nasl", "gb_ucs_detect.nasl", "gb_cwp_consolidation.nasl",
                      "gb_microsoft_iis_http_detect.nasl",
                      "sw_http_os_detection.nasl", "sw_mail_os_detection.nasl",
                      "sw_telnet_os_detection.nasl", "gb_mysql_mariadb_os_detection.nasl",
                      "gb_apcnisd_detect.nasl", "gb_dahua_devices_http_detect.nasl",
                      "gb_amcrest_ip_camera_http_detect.nasl", "gb_pptp_os_detection.nasl",
                      "gb_f5_enterprise_manager_http_detect.nasl", "gb_f5_enterprise_manager_ssh_login_detect.nasl",
                      "gb_ntp_os_detection.nasl", "mdns_service_detection.nasl",
                      "gb_microsoft_sql_server_tcp_ip_listener_detect.nasl", "gb_apple_tv_version.nasl",
                      "gb_apple_tv_detect.nasl", "gb_upnp_os_detection.nasl",
                      "gb_sip_os_detection.nasl", "gb_checkmk_agent_detect.nasl",
                      "ms_rdp_detect.nasl", "gb_schneider_ecostruxure_geo_scada_expert_http_detect.nasl",
                      "dcetest.nasl", "gb_fsecure_internet_gatekeeper_http_detect.nasl",
                      "secpod_ocs_inventory_ng_detect.nasl", "gb_hnap_os_detection.nasl",
                      "gb_ident_os_detection.nasl", "gb_pi-hole_http_detect.nasl",
                      "gb_citrix_xenmobile_http_detect.nasl", "gb_dnsmasq_consolidation.nasl",
                      "gb_dropbear_consolidation.nasl", "gb_monit_detect.nasl",
                      "gb_rtsp_os_detection.nasl", "gb_netapp_storagegrid_http_detect.nasl",
                      "gb_solarwinds_sam_http_detect.nasl",
                      "gb_nntp_os_detection.nasl", "gb_siemens_sinema_server_detect.nasl",
                      "gb_microsoft_exchange_outlook_web_app_http_detect.nasl", "gb_openvas_manager_detect.nasl",
                      "gb_greenbone_gsa_http_detect.nasl", "gb_aerospike_consolidation.nasl",
                      "gb_artica_proxy_http_detect.nasl", "gb_microfocus_filr_consolidation.nasl",
                      "gb_altn_mdaemon_consolidation.nasl", "gb_elastix_http_detect.nasl",
                      "gb_solarwinds_orion_npm_consolidation.nasl", "sw_f5_firepass_http_detect.nasl",
                      "gb_gate_one_http_detect.nasl", "gb_kaseya_vsa_detect.nasl",
                      "gb_manageengine_adaudit_plus_http_detect.nasl",
                      "gb_manageengine_admanager_plus_consolidation.nasl",
                      "gb_manageengine_exchange_reporter_http_detect.nasl",
                      "gb_home_assistant_consolidation.nasl", "gb_op5_http_detect.nasl",
                      "gb_veritas_netbackup_appliance_http_detect.nasl",
                      "gb_southrivertech_titan_ftp_server_consolidation.nasl",
                      "gb_dell_powerscale_insightiq_http_detect.nasl", "gb_weborf_http_detect.nasl",
                      "gb_gitlab_consolidation.nasl", "gb_sitecore_http_detect.nasl",
                      "gb_cisco_small_business_devices_consolidation.nasl", "gb_lmtp_service_detect.nasl",
                      "gb_moxa_mxview_consolidation.nasl", "gb_suremdm_server_http_detect.nasl",
                      "gb_bmc_trackit_http_detect.nasl", "gb_zabbix_http_detect.nasl",
                      "gb_vmware_nsx_consolidation.nasl", "gb_sony_network_camera_http_detect.nasl",
                      "gb_opennms_http_detect.nasl", "gb_graylog_consolidation.nasl",
                      "gb_hikvision_ip_camera_http_detect.nasl", "gb_dotnetnuke_consolidation.nasl",
                      "gb_progress_ws_ftp_server_consolidation.nasl", "gb_zimbra_consolidation.nasl",
                      "gb_openwrt_ssh_login_detect.nasl", "gb_koha_http_detect.nasl",
                      "gb_xerox_docushare_http_detect.nasl", "gb_zyxel_nas_http_detect.nasl",
                      "gb_zyxel_router_consolidation.nasl", "gb_sitefinity_http_detect.nasl",
                      "gb_timelive_http_detect.nasl", "gb_open-xchange_ox_app_suite_http_detect.nasl",
                      "gb_gunicorn_http_detect.nasl", "gb_sonesix_conference_manager_http_detect.nasl",
                      "gb_teamspeak_server_tcp_detect.nasl", "gb_mailenable_consolidation.nasl",
                      "gb_f5_big_ip_ssh_login_detect.nasl",
                      "gb_ultidev_cassini_http_detect.nasl", "gb_aas_http_detect.nasl",
                      "gb_progress_whatsup_consolidation.nasl", "gb_sogo_http_detect.nasl",
                      "gb_apache_ambari_http_detect.nasl", "gb_docker_http_rest_api_detect.nasl",
                      "gb_adobe_connect_http_detect.nasl", "gb_wsman_winrm_http_detect.nasl",
                      "gb_microsoft_msmq_tcp_detect.nasl", "gb_redhat_openshift_http_detect.nasl",
                      "gb_tenable_nessus_consolidation.nasl", "gb_adobe_robohelp_server_http_detect.nasl",
                      "gb_nagios_xi_http_detect.nasl", "gb_digium_asterisk_sip_detect.nasl",
                      "gb_splunk_http_detect.nasl", "gb_barracuda_web_application_firewall_consolidation.nasl",
                      "gb_symantec_messaging_gateway_consolidation.nasl", "gb_rspamd_http_detect.nasl",
                      "gb_bitvise_ssh_server_consolidation.nasl", "gb_cisco_vcs_consolidation.nasl",
                      "sw_tinyproxy_http_detect.nasl", "gb_ibm_qradar_siem_consolidation.nasl",
                      "gb_f5_linerate_ssh_login_detect.nasl", "gb_f5_linerate_http_detect.nasl",
                      "gb_froxlor_http_detect.nasl", "gb_f5_big_ip_http_detect.nasl",
                      "gb_freepbx_http_detect.nasl", "gb_freeipa_http_detect.nasl",
                      "gb_dell_avamar_consolidation.nasl", "gb_ibm_storwize_consolidation.nasl",
                      "gb_logsign_http_detect.nasl", "gb_netiq_access_manager_http_detect.nasl",
                      "gb_fortinet_fortiweb_consolidation.nasl", "gb_fortinet_fortimanager_consolidation.nasl",
                      "gb_fortinet_fortianalyzer_consolidation.nasl",
                      "gb_cups_http_detect.nasl", "gb_palo_alto_expedition_http_detect.nasl",
                      "gb_zkteco_zkbiosecurity_http_detect.nasl", "gb_collabora_libreoffice_online_http_detect.nasl",
                      "gb_kentico_cms_http_detect.nasl", "gb_apache_atlas_http_detect.nasl",
                      "gb_nuuo_devices_http_detect.nasl", "gb_apache_ranger_http_detect.nasl",
                      "gb_cyberark_password_vault_http_detect.nasl", "gb_tandberg_devices_detect.nasl",
                      "gb_nagios_log_server_http_detect.nasl", "mailman_http_detect.nasl",
                      "gb_postorius_http_detect.nasl", "gb_cisco_nfvis_http_detect.nasl",
                      "gb_infoblox_netmri_consolidation.nasl", "gb_puppet_enterprise_consolidation.nasl",
                      "gb_cisco_ucs_platform_emulator_http_detect.nasl",
                      "gb_android_adb_detect.nasl", "netbios_name_get.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_synetica_datastream_devices_telnet_detect.nasl",
                        "gsf/gb_f5_big-ip_next_central_manager_consolidation.nasl",
                        "gsf/gb_f5_big-ip_next_http_detect.nasl",
                        "gsf/gb_f5_f5os_http_detect.nasl",
                        "gsf/gb_paloalto_globalprotect_portal_http_detect.nasl",
                        "gsf/gb_cisco_vision_dynamic_signage_director_detect.nasl",
                        "gsf/gb_tibco_loglogic_http_detect.nasl",
                        "gsf/gb_inea_me-rtu_http_detect.nasl",
                        "gsf/gb_fortinet_fortios_sslvpn_portal_detect.nasl",
                        "gsf/gb_mult_vendors_wlan_controller_aps_detection.nasl",
                        "gsf/gb_dell_emc_powerconnect_consolidation.nasl",
                        "gsf/gb_cisco_ind_http_detect.nasl",
                        "gsf/gb_cisco_csm_http_detect.nasl",
                        "gsf/gb_silverpeak_appliance_consolidation.nasl",
                        "gsf/gb_ewon_flexy_cosy_http_detect.nasl",
                        "gsf/gb_optergy_proton_consolidation.nasl",
                        "gsf/gb_unitronics_plc_pcom_detect.nasl",
                        "gsf/gb_sonicwall_email_security_consolidation.nasl",
                        "gsf/gb_ruckus_zonedirector_consolidation.nasl",
                        "gsf/gb_honeywell_ip-ak2_http_detect.nasl",
                        "gsf/gb_siemens_sppa-t3000_app_server_http_detect.nasl",
                        "gsf/gb_timetools_ntp_server_http_detect.nasl",
                        "gsf/gb_aruba_switches_consolidation.nasl",
                        "gsf/gb_trendmicro_apex_central_consolidation.nasl",
                        "gsf/gb_auerswald_compact_consolidation.nasl",
                        "gsf/gb_auerswald_commander_consolidation.nasl",
                        "gsf/gb_auerswald_comfortel_http_detect.nasl",
                        "gsf/gb_beckhoff_ads_udp_detect.nasl",
                        "gsf/gb_apache_activemq_jms_detect.nasl",
                        "gsf/gb_citrix_sharefile_storagezones_controller_consolidation.nasl",
                        "gsf/gb_konicaminolta_printer_consolidation.nasl",
                        "gsf/gb_ibm_spectrum_protect_plus_consolidation.nasl",
                        "gsf/gb_nimbus_os_detection.nasl",
                        "gsf/gb_secomea_gatemanager_http_detect.nasl",
                        "gsf/gb_symantec_endpoint_protection_manager_http_detect.nasl",
                        "gsf/gb_vxworks_consolidation.nasl",
                        "gsf/gb_spinetix_player_http_detect.nasl",
                        "gsf/gb_spinetix_fusion_http_detect.nasl",
                        "gsf/gb_mobileiron_sentry_http_detect.nasl",
                        "gsf/gb_bigbluebutton_consolidation.nasl",
                        "gsf/gb_observium_http_detect.nasl",
                        "gsf/gb_ruckus_iot_controller_http_detect.nasl",
                        "gsf/gb_contiki_os_http_detect.nasl",
                        "gsf/gb_ethernut_http_detect.nasl",
                        "gsf/gb_solarwinds_orion_platform_consolidation.nasl",
                        "gsf/gb_ui_edgepower_consolidation.nasl",
                        "gsf/gb_zyxel_usg_consolidation.nasl",
                        "gsf/gb_cisco_dna_center_http_detect.nasl",
                        "gsf/gb_magicflow_msa_gateway_http_detect.nasl",
                        "gsf/gb_cisco_smart_software_manager_on_prem_http_detect.nasl",
                        "gsf/gb_apache_druid_http_detect.nasl",
                        "gsf/gb_abb_ac500_opcua_detect.nasl",
                        "gsf/gb_netmotion_mobility_server_http_detect.nasl",
                        "gsf/gb_samsung_wlan_ap_http_detect.nasl",
                        "gsf/gb_cisco_sdwan_vmanage_consolidation.nasl",
                        "gsf/gb_schneider_powerlogic_consolidation.nasl",
                        "gsf/gb_nexusdb_http_detect.nasl",
                        "gsf/gb_rzk_dolusoft_fortilogger_http_detect.nasl",
                        "gsf/gb_yealink_device_management_http_detect.nasl",
                        "gsf/gb_inspur_clusterengine_http_detect.nasl",
                        "gsf/gb_passbolt_consolidation.nasl",
                        "gsf/gb_vmware_view_planner_http_detect.nasl",
                        "gsf/gb_omnissa_workspace_one_uem_http_detect.nasl",
                        "gsf/gb_netapp_cloud_manager_http_detect.nasl",
                        "gsf/gb_vmware_workspace_one_access_http_detect.nasl",
                        "gsf/gb_cisco_meraki_consolidation.nasl",
                        "gsf/gb_clickstudios_passwordstate_consolidation.nasl",
                        "gsf/gb_kemp_loadmaster_consolidation.nasl",
                        "gsf/gb_voipmonitor_http_detect.nasl",
                        "gsf/gb_ivanti_avalanche_consolidation.nasl",
                        "gsf/gb_blackberry_uem_http_detect.nasl",
                        "gsf/gb_flir_ax8_consolidation.nasl",
                        "gsf/gb_flir_a3xx_series_consolidation.nasl",
                        "gsf/gb_flir_neco_platform_ssh_login_detect.nasl",
                        "gsf/gb_cisco_hyperflex_data_platform_http_detect.nasl",
                        "gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.nasl",
                        "gsf/gb_tg8_firewall_http_detect.nasl",
                        "gsf/gb_maipu_network_device_http_detect.nasl",
                        "gsf/gb_cisco_sdwan_vedge_ssh_login_detect.nasl",
                        "gsf/gb_akkadian_provisioning_manager_http_detect.nasl",
                        "gsf/gb_circontrol_circarlife_http_detect.nasl",
                        "gsf/gb_circontrol_raption_http_detect.nasl",
                        "gsf/gb_sonicwall_nsm_http_detect.nasl",
                        "gsf/gb_dell_wyse_management_suite_http_detect.nasl",
                        "gsf/gb_philips_vue_pacs_http_detect.nasl",
                        "gsf/gb_philips_vue_motion_http_detect.nasl",
                        "gsf/gb_aruba_instant_http_detect.nasl",
                        "gsf/gb_elastic_cloud_enterprise_http_detect.nasl",
                        "gsf/gb_aapanel_http_detect.nasl",
                        "gsf/gb_ruijie_devices_http_detect.nasl",
                        "gsf/gb_cisco_firepower_device_manager_http_detect.nasl",
                        "gsf/gb_manageengine_adselfservice_plus_http_detect.nasl",
                        "gsf/gb_fatpipe_http_detect.nasl",
                        "gsf/gb_cisco_intersight_http_detect.nasl",
                        "gsf/gb_cisco_nexus_dashboard_http_detect.nasl",
                        "gsf/gb_vmware_horizon_http_detect.nasl",
                        "gsf/gb_ivanti_cloud_services_appliance_consolidation.nasl",
                        "gsf/gb_sonicwall_ns_snmp_detect.nasl",
                        "gsf/gb_turck_consolidation.nasl",
                        "gsf/gb_franklin_fueling_systems_device_http_detect.nasl",
                        "gsf/gb_siemens_sicam_a8000_http_detect.nasl",
                        "gsf/gb_zyxel_vpn_firewall_consolidation.nasl",
                        "gsf/gb_zyxel_atp_consolidation.nasl",
                        "gsf/gb_zyxel_nxc_consolidation.nasl",
                        "gsf/gb_zyxel_nap_http_detect.nasl",
                        "gsf/gb_zyxel_switch_consolidation.nasl",
                        "gsf/gb_zyxel_nwa_http_detect.nasl",
                        "gsf/gb_hp_3com_switch_consolidation.nasl",
                        "gsf/gb_citrix_adm_consolidation.nasl",
                        "gsf/gb_zyxel_wac_consolidation.nasl",
                        "gsf/gb_zyxel_wax_consolidation.nasl",
                        "gsf/gb_zyxel_uag_consolidation.nasl",
                        "gsf/gb_contec_solarview_compact_http_detect.nasl",
                        "gsf/gb_ndmp_get_info.nasl",
                        "gsf/gb_vmware_hcx_http_detect.nasl",
                        "gsf/gb_ericsson_mini-link_consolidation.nasl",
                        "gsf/gb_7signal_sonar_http_detect.nasl",
                        "gsf/gb_avaya_contact_center_select_http_detect.nasl",
                        "gsf/gb_rstudio_connect_http_detect.nasl",
                        "gsf/gb_cynet_360_http_detect.nasl",
                        "gsf/gb_fortinet_fortiportal_http_detect.nasl",
                        "gsf/gb_fortinet_fortitester_http_detect.nasl",
                        "gsf/gb_fortinet_fortiproxy_consolidation.nasl",
                        "gsf/gb_fortinet_fortiddos_consolidation.nasl",
                        "gsf/gb_progress_datadirect_hybrid_data_pipeline_http_detect.nasl",
                        "gsf/gb_ruckus_virtual_smartzone_http_detect.nasl",
                        "gsf/gb_ruckus_smartzone_http_detect.nasl",
                        "gsf/gb_vmware_workspace_one_assist_http_detect.nasl",
                        "gsf/gb_barracuda_cloudgen_firewall_consolidation.nasl",
                        "gsf/gb_barracuda_cloudgen_based_device_ssh_login_detect.nasl",
                        "gsf/gb_solarwinds_sem_consolidation.nasl",
                        "gsf/gb_dlink_devices_hnap_detect.nasl",
                        "gsf/gb_dlink_devices_mdns_detect.nasl",
                        "gsf/gb_dlink_devices_upnp_detect.nasl",
                        "gsf/gb_dlink_dnh_consolidation.nasl",
                        "gsf/gb_vmware_vrni_consolidation.nasl",
                        "gsf/gb_securepoint_utm_http_detect.nasl",
                        "gsf/gb_manageengine_ad360_http_detect.nasl",
                        "gsf/gb_manageengine_endpoint_dlp_plus_http_detect.nasl",
                        "gsf/gb_manageengine_patch_manager_plus_http_detect.nasl",
                        "gsf/gb_barox_switch_snmp_detection.nasl",
                        "gsf/gb_ruckus_smartcell_http_detect.nasl",
                        "gsf/gb_fortinet_fortiadc_consolidation.nasl",
                        "gsf/gb_fortinet_fortinac_http_detect.nasl",
                        "gsf/gb_fortinet_fortisiem_consolidation.nasl",
                        "gsf/gb_fortinet_fortiswitch_consolidation.nasl",
                        "gsf/gb_alcatel_omniswitch_consolidation.nasl",
                        "gsf/gb_connectwise_r1soft_sbm_http_detect.nasl",
                        "gsf/gb_dlink_generic_device_consolidation.nasl",
                        "gsf/gb_vmware_esxi_openslp_udp_detect.nasl",
                        "gsf/gb_vmware_esxi_openslp_tcp_detect.nasl",
                        "gsf/gb_barracuda_cloudgen_wan_consolidation.nasl",
                        "gsf/gb_arrayos_consolidation.nasl",
                        "gsf/gb_apsystems_energy_communication_unit_http_detect.nasl",
                        "gsf/gb_checkmk_appliance_http_detect.nasl",
                        "gsf/gb_apache_superset_http_detect.nasl",
                        "gsf/gb_oracle_opera_http_detect.nasl",
                        "gsf/gb_cpanel_http_detect.nasl",
                        "gsf/gb_sophos_mobile_http_detect.nasl",
                        "gsf/gb_phoenixcontact_plc_device_pcworx_detect.nasl",
                        "gsf/gb_moxa_mxsecurity_consolidation.nasl",
                        "gsf/gb_barracuda_email_security_gateway_consolidation.nasl",
                        "gsf/gb_progress_moveit_transfer_consolidation.nasl",
                        "gsf/gb_edgecore_device_http_detect.nasl",
                        "gsf/gb_fortra_globalscape_eft_consolidation.nasl",
                        "gsf/gb_microsoft_skype_for_business_server_http_detect.nasl",
                        "gsf/gb_ubiquiti_edgerouter_consolidation.nasl",
                        "gsf/gb_cloudpanel_http_detect.nasl",
                        "gsf/gb_vmware_sdwan_edge_http_detect.nasl",
                        "gsf/gb_rockwell_controllogix_consolidation.nasl",
                        "gsf/gb_mitel_smb_controller_http_detect.nasl",
                        "gsf/gb_ivanti_epm_consolidation.nasl",
                        "gsf/gb_polycom_ipphone_consolidation.nasl",
                        "gsf/gb_siemens_logo_plc_http_detect.nasl",
                        "gsf/gb_sangfor_ngaf_http_detect.nasl",
                        "gsf/gb_honeywell_printer_consolidation.nasl",
                        "gsf/gb_supermicro_bmc_consolidation.nasl",
                        "gsf/gb_jumpserver_http_detect.nasl",
                        "gsf/gb_viessmann_vitogate_http_detect.nasl",
                        "gsf/gb_solarwinds_arm_http_detect.nasl",
                        "gsf/gb_veeam_one_consolidation.nasl",
                        "gsf/gb_qlik_sense_consolidation.nasl",
                        "gsf/gb_manageengine_m365_security_plus_consolidation.nasl",
                        "gsf/gb_manageengine_endpoint_central_server_consolidation.nasl",
                        "gsf/gb_manageengine_endpoint_central_server_msp_consolidation.nasl",
                        "gsf/gb_aveva_intouch_access_anywhere_http_detect.nasl",
                        "gsf/gb_aveva_plant_scada_access_anywhere_http_detect.nasl",
                        "gsf/gb_vinchin_backup_recovery_http_detect.nasl",
                        "gsf/gb_sonicwall_firewall_http_detect.nasl",
                        "gsf/gb_glinet_devices_http_detect.nasl",
                        "gsf/gb_cisco_expressway_consolidation.nasl",
                        "gsf/gb_adobe_framemaker_publishing_server_http_detect.nasl",
                        "gsf/gb_progress_openedge_http_detect.nasl",
                        "gsf/gb_aruba_clearpass_policy_manager_consolidation.nasl",
                        "gsf/gb_arista_ng_firewall_http_detect.nasl",
                        "gsf/gb_devolutions_server_http_detect.nasl",
                        "gsf/gb_ivanti_neurons_for_itsm_consolidation.nasl",
                        "gsf/gb_progress_telerik_report_server_http_detect.nasl",
                        "gsf/gb_progress_flowmon_http_detect.nasl",
                        "gsf/gb_vmware_sdwan_orchestrator_http_detect.nasl",
                        "gsf/gb_inotec_cps_http_detect.nasl",
                        "gsf/gb_dell_openmanage_enterprise_http_detect.nasl",
                        "gsf/gb_mitel_ip_phones_consolidation.nasl",
                        "gsf/gb_recrystallize_server_http_detect.nasl",
                        "gsf/gb_kemp_ecs_connection_manager_consolidation.nasl",
                        "gsf/gb_vmware_avi_load_balancer_consolidation.nasl",
                        "gsf/gb_veeam_service_provider_console_consolidation.nasl",
                        "gsf/gb_f5_big-ip_snmp_detect.nasl",
                        "gsf/gb_opentext_dimensions_rm_http_detect.nasl",
                        "gsf/gb_avideo_platform_http_detect.nasl",
                        "gsf/gb_fortra_tripwire_enterprise_http_detect.nasl",
                        "gsf/gb_dell_emc_smartfabric_os10_consolidation.nasl",
                        "gsf/gb_zkbio_cvsecurity_http_detect.nasl",
                        "gsf/gb_veeam_backup_replication_server_consolidation.nasl",
                        "gsf/gb_pexip_infinity_http_detect.nasl",
                        "gsf/gb_mailcow_consolidation.nasl",
                        "gsf/gb_juniper_ssr_consolidation.nasl",
                        "gsf/gb_moxa_oncell_consolidation.nasl",
                        "gsf/gb_stormshield_sns_consolidation.nasl",
                        "gsf/gb_schneider_modicon_controller_consolidation.nasl",
                        "gsf/gb_schneider_powerlogic_protection_ssh_login_detect.nasl",
                        "gsf/gb_softing_edgeaggregator_http_detect.nasl",
                        "gsf/gb_softing_edgeconnector_http_detect.nasl",
                        "gsf/gb_ivanti_virtual_traffic_manager_http_detect.nasl",
                        "gsf/gb_ada_web_server_http_detect.nasl",
                        "gsf/gb_mitel_mivoice_mx-one_http_detect.nasl",
                        "gsf/gb_openbmc_consolidation.nasl",
                        "gsf/gb_avaya_system_manager_consolidation.nasl",
                        "gsf/gb_lg_simple_editor_http_detect.nasl",
                        "gsf/gb_delta_electronics_diaenergie_consolidation.nasl",
                        "gsf/gb_versa_director_consolidation.nasl",
                        "gsf/gb_controlid_idsecure_http_detect.nasl",
                        "gsf/gb_watchguard_sso_agent_telnet_detect.nasl",
                        "gsf/gb_acronis_cyber_infrastructure_http_detect.nasl",
                        "gsf/gb_elvaco_cme_http_detect.nasl",
                        "gsf/gb_cyberpanel_http_detect.nasl",
                        "gsf/gb_dell_secure_connect_gateway_consolidation.nasl",
                        "gsf/gb_ibm_security_verify_access_http_detect.nasl",
                        "gsf/gb_apache_kylin_http_detect.nasl",
                        "gsf/gb_abb_aspect_consolidation.nasl",
                        "gsf/gb_apache_hertzbeat_http_detect.nasl",
                        "gsf/gb_poly_videoconference_consolidation.nasl",
                        "gsf/gb_sailpoint_identityiq_http_detect.nasl",
                        "gsf/gb_four_faith_router_http_detect.nasl",
                        "gsf/gb_aviatrix_controller_http_detect.nasl",
                        "gsf/gb_opentext_solutions_business_manager_http_detect.nasl",
                        "gsf/gb_aruba_fabric_composer_http_detect.nasl",
                        "gsf/gb_wazuh_dashboard_http_detect.nasl",
                        "gsf/gb_audiocodes_ovoc_http_detect.nasl",
                        "gsf/gb_audiocodes_sbc_consolidation.nasl",
                        "gsf/gb_trimble_cityworks_http_detect.nasl",
                        "gsf/gb_rockwell_guardlogix_ethernetip_detect.nasl",
                        "gsf/gb_beyondtrust_secure_remote_access_appliance_http_detect.nasl",
                        "gsf/gb_beyondtrust_beyondinsight_http_detect.nasl",
                        "gsf/gb_ubiquiti_unifi_os_consolidation.nasl",
                        "gsf/gb_liebert_crv_consolidation.nasl",
                        "gsf/gb_hirsch_enterphone_mesh_http_detect.nasl",
                        "gsf/gb_veeam_backup_for_salesforce_http_detect.nasl",
                        "gsf/gb_mult_network_cameras_http_detect.nasl",
                        "gsf/gb_redhat_satellite_http_detect.nasl",
                        "gsf/gb_apache_pinot_http_detect.nasl",
                        "gsf/gb_connectwise_screenconnect_http_detect.nasl",
                        "gsf/gb_apache_answer_http_detect.nasl",
                        "gsf/gb_opnsense_consolidation.nasl",
                        "gsf/gb_opentext_advanced_authentication_http_detect.nasl",
                        "gsf/gb_seppmail_secure_email_gateway_consolidation.nasl",
                        "gsf/gb_versa_concerto_http_detect.nasl",
                        "gsf/gb_cisco_secure_networks_analytics_http_detect.nasl",
                        "gsf/gb_samsung_magicinfo_server_http_detect.nasl",
                        "gsf/gb_zkbio_time_http_detect.nasl",
                        "gsf/gb_huawei_esight_consolidation.nasl",
                        "gsf/gb_mici_network_fax_http_detect.nasl",
                        "gsf/gb_sunbird_dcim_dctrack_http_detect.nasl",
                        "gsf/gb_huawei_fusionsphere_cps_consolidation.nasl",
                        "gsf/gb_vmware_nsx_data_center_consolidation.nasl",
                        "gsf/gb_huawei_fusionsphere_om_consolidation.nasl",
                        "gsf/gb_abb_eibport_http_detect.nasl",
                        "gsf/gb_hpe_storeonce_http_detect.nasl",
                        "gsf/gb_zendto_http_detect.nasl",
                        "gsf/gb_sitecore_identity_server_http_detect.nasl",
                        "gsf/gb_advantech_wise_http_detect.nasl",
                        "gsf/gb_netbox_http_detect.nasl",
                        "gsf/gb_checkbox_survey_http_detect.nasl",
                        "gsf/gb_cisco_spaces_connector_consolidation.nasl",
                        "gsf/gb_gfi_archiver_http_detect.nasl",
                        "gsf/gb_hpe_instant_on_ap_http_detect.nasl",
                        "gsf/gb_hpe_instant_on_switch_snmp_detect.nasl",
                        "gsf/gb_xorux_xormon_http_detect.nasl",
                        "gsf/gb_xorux_lpar2rrd_http_detect.nasl",
                        "gsf/gb_ubiquiti_edgeswitch_consolidation.nasl",
                        "gsf/gb_n-able_n-central_http_detect.nasl",
                        "gsf/gb_pandora_itsm_http_detect.nasl",
                        "gsf/gb_securden_unified_pam_http_detect.nasl",
                        "gsf/gb_dell_cloudlink_http_detect.nasl",
                        "gsf/gb_xorcom_completepbx_consolidation.nasl"
                      );

  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_add_preference(name:"Run routine", type:"checkbox", value:"yes", id:1);

  script_xref(name:"URL", value:"http://www.phrack.org/issues.html?issue=57&id=7#article");

  script_tag(name:"summary", value:"ICMP based OS fingerprinting / detection.");

  script_tag(name:"insight", value:"This script performs ICMP based OS fingerprinting (as
  described by Ofir Arkin and Fyodor Yarochkin in Phrack #57). It can be used to determine
  the remote OS and partly it's version.

  Note: This routine / method is false positive prone (especially in virtualized
  environments) and only the last resort if any other OS detection method is failing). Due
  to this it is possible to disable this routine via the script preferences.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

# Allow the user to disable this routine for the reasons explained in the script summary.
run_routine = script_get_preference( "Run routine", id:1 );
if( run_routine && "no" >< run_routine )
  exit( 0 );

if( TARGET_IS_IPV6() )
  exit( 0 );

# nb: We only want to run this VT as a "last fallback" if all of the other
# more reliable OS detections failed. This VT isn't that reliable these days
# and takes around 10 seconds (or even more) for each host to finish.
reports = get_kb_list( "os_detection_report/reports/*" );
if( reports && max_index( keys( reports ) ) > 0 )
  exit( 0 );

ATTEMPTS = 2;
passed = 0;

include("host_details.inc");
include("os_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (ICMP)";

# Fingerprints extracted from xprobe2.conf
# -----
# The fingerprints table is divided into sections. Each section starts with its
# label, followed by the corresponding fingerprints. An empty string closes the
# section.
# In case there are several matches for the remote OS, then the section title(s)
# will be displayed instead of the whole list of matches.

FINGERPRINTS = make_list(
    "AIX,cpe:/o:ibm:aix",
        "AIX 5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
        "AIX 4.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
    "",
    "Apple Mac OS X,cpe:/o:apple:mac_os_x",
        "Apple Mac OS X 10.2.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.2,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.3,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.4,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.5,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.6,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.7,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.8,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.9,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.4.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.4.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
    "",
    "Cisco IOS,cpe:/o:cisco:ios",
        "Cisco IOS 12.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 12.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 12.0,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.1,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
    "",
    "FreeBSD,cpe:/o:freebsd:freebsd",
        "FreeBSD 5.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.11,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.10,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.9,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.6.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.1.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 2.2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 2.2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
    "",
    "HP UX,cpe:/o:hp:hp-ux",
        "HP UX 11.0x,y,!0,!0,!0,1,<255,n,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "HP UX 11.0,y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
    "",
    "HP JetDirect,cpe:/h:hp:jetdirect",
        "HP JetDirect ROM A.03.17 EEPROM A.04.09,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM A.05.03 EEPROM A.05.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM F.08.01 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM F.08.08 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM F.08.08 EEPROM F.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.05.34 EEPROM G.05.35,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM G.06.00 EEPROM G.06.00,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.07.17,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.08.03,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.08.08 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.08.21 EEPROM G.08.21,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM H.07.15 EEPROM H.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM L.20.07 EEPROM L.20.24,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
        "HP JetDirect ROM R.22.01 EEPROM L.24.08,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
    "",
    "Linux Kernel,cpe:/o:linux:kernel",
        "Linux Kernel 2.6.11,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.10,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.9,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.8,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.7,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.6,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.5,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.4,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.3,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.2,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.1,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.0,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.29,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.28,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.27,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.26,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.25,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.24,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.23,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.22,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.21,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.20,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.19,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.4 (I),y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.4,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.3,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.2,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.1,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.0,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.26,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.25,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.24,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.23,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.22,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.21,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.20,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.19,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.4,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.3,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.36,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.34,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
    "",
    "Microsoft Windows,cpe:/o:microsoft:windows",
        "Microsoft Windows 2003 Server Enterprise Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2003 Server Standard Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows Millennium Edition (ME),y,0,!0,!0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 98 Second Edition (SE),y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 98,y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 95,y,0,!0,!0,1,<32,n,!0,<32,y,!0,<32,n,!0,<32,y,0,0,!0,8,<32,OK,OK,OK,OK,OK",
    "",
    "NetBSD,cpe:/o:netbsd:netbsd",
        "NetBSD 2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
    "",
    "OpenBSD,cpe:/o:openbsd:openbsd",
        "OpenBSD 3.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 2.9,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 2.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
    "",
    "Sun Solaris,cpe:/o:sun:sunos",
        "Sun Solaris 10 (SunOS 5.10),y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 9 (SunOS 5.9),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 8 (SunOS 2.8),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 7 (SunOS 2.7),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 6 (SunOS 2.6),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 2.5.1,y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
    ""
);


function _TTL(ttl) {
    if (ttl <= 32)       num = 32;
    else if (ttl <= 64)  num = 64;
    else if (ttl <= 128) num = 128;
    else                 num = 255;

    return "<" + num;
}


# ModuleA()
#
#   ICMP Echo probe
#   Sends an ICMP Echo Request and generates a fingerprint from returned
#   packet's IP and ICMP headers.

function ModuleA() {

    # We might already know from host_alive_detection.nasl that the target is not answering
    # to ICMP Echo request so directly return right away. This saves 2 seconds
    # for such a target.
    if( get_kb_item( "ICMPv4/EchoRequest/failed" ) ) return "n,,,,,";

    ICMP_ECHO_REQUEST = 8;

    # We will set the IP_ID to constant number. Further more that number
    # needs to be symmetric so we can easily work around the NASL bug.
    # The bug comes from get_ip_element() when we try to extract IP_ID
    # field...the IP_ID field comes out flipped. For example: SENT
    # IP_ID:0xAABB, extracted RECV IP_ID: 0xBBAA

    IP_ID = 0xBABA;

    ICMP_ID = rand() % 65536;
    ip_packet =
        forge_ip_packet(ip_tos : 6,
                        ip_id  : IP_ID,
                        ip_off : IP_DF,        # DON'T FRAGMENT flag
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_ECHO_REQUEST,
                          icmp_code : 123,
                          icmp_seq  : 256,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);
    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {

        # pcap filter matches the ICMP Echo Reply packet with the same
        # ID as the original Echo Request packet

        filter = "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 0" +
                 " and icmp[4:2] = " + ICMP_ID;

        ret = send_packet(icmp_packet, pcap_active : TRUE,
                pcap_filter : filter, pcap_timeout : 1);
    }

    # icmp_echo_reply
    # icmp_echo_code
    # icmp_echo_ip_id
    # icmp_echo_tos_bits
    # icmp_echo_df_bit
    # icmp_echo_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result = "y";

        if (get_icmp_element(element : "icmp_code", icmp : ret) == 0)
            result += ",0";
        else
            result += ",!0";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        if (get_ip_element(element : "ip_tos", ip : ret) == 0)
            result += ",0";
        else
            result += ",!0";

        if (get_ip_element(element : "ip_off", ip : ret) & IP_DF)
            result += ",1";
        else
            result += ",0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {

        # ICMP Echo Reply not received

        result = "n,,,,,";
    }

    return result;
}


# ModuleB()
#
#   ICMP Timestamp probe
#   Sends an ICMP Timestamp packet and generates a fingerprint from returned
#   packet's (ICMP Timestamp Reply) IP and ICMP headers.

function ModuleB() {
    ICMP_TIMESTAMP = 13;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_TIMESTAMP,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 14" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_timestamp_reply
    # icmp_timestamp_reply_ip_id
    # icmp_timestamp_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        # For later use in e.g. 2011/gb_icmp_timestamps.nasl
        set_kb_item( name:"ICMPv4/TimestampRequest/failed", value:TRUE );
        result += "n,,";
    }

    return result;
}


# ModuleC()
#
#   ICMP Address Mask probe
#   Sends an ICMP Address Mask Request and generates a fingerprint from
#   returned packet's IP and ICMP headers.

function ModuleC() {
    ICMP_ADDRMASK = 17;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_ADDRMASK,
                          icmp_id   : ICMP_ID,
                          data      : crap(length:4, data:raw_string(0)),
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 18" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_addrmask_reply
    # icmp_addrmask_reply_ip_id
    # icmp_addrmask_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        # For later use by other VTs
        set_kb_item( name:"ICMPv4/AddressMaskRequest/failed", value:TRUE );
        result += "n,,";
    }

    return result;
}


# ModuleD()
#
#   ICMP Info Request probe

function ModuleD() {
    ICMP_INFOREQ = 15;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_INFOREQ,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 16" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_info_reply
    # icmp_info_reply_ip_id
    # icmp_info_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        # For later use by other VTs
        set_kb_item( name:"ICMPv4/InfoRequest/failed", value:TRUE );
        result = "n,,";
    }

    return result;
}


# ModuleE()
#
#   ICMP Port Unreachable probe

function ModuleE() {
    ICMP_UNREACH_DEF_PORT = 65534;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_UDP,
                        ip_off : IP_DF,
                        ip_src : this_host());
    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        dport = ICMP_UNREACH_DEF_PORT - attempt;
        udp_packet =
            forge_udp_packet(
                                data     : crap(70),
                                ip       : ip_packet,
                                uh_dport : dport,
                                uh_sport : 53
                             );

        # ICMP Port Unreachable packet contains our sent packet
        ret = send_packet(udp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 3" +
                " and icmp[1:1] = 3 " +
                " and icmp[30:2] = " + dport);

    }

    # icmp_unreach_reply
    # icmp_unreach_precedence_bits
    # icmp_unreach_df_bit
    # icmp_unreach_ip_id
    # icmp_unreach_echoed_dtsize
    # icmp_unreach_reply_ttl
    # icmp_unreach_echoed_udp_cksum
    # icmp_unreach_echoed_ip_cksum
    # icmp_unreach_echoed_ip_id
    # icmp_unreach_echoed_total_len
    # icmp_unreach_echoed_3bit_flags

    result = "";
    if (ret) {
        passed = 1;

        # IP_Header_of_the_UDP_Port_Unreachable_error_message

        result += "y";

        # icmp_unreach_precedence_bits = 0xc0, 0, (hex num)

        tos = get_ip_element(ip:ret, element:"ip_tos");
        if (tos == 0xc0)
            result += ",0xc0";
        else if (tos == 0)
            result += ",0";
        else
            result += ",!0";

        # icmp_unreach_df_bit = [0 , 1 ]
        # we cannot access only df bit or 3bitflags. we access
        # 3_bit_flags + frag_offset

        _3bit_flag_frag_off = get_ip_element(ip:ret, element:"ip_off");
        if (_3bit_flag_frag_off & IP_DF)
            result += ",1";
        else
            result += ",0";

        #icmp_unreach_ip_id = [0, !0, SENT]

        received_id = get_ip_element(ip:ret, element:"ip_id");
        if (received_id == IP_ID)
            result += ",SENT";
        else if (received_id == 0)
            result += ",0";
        else
            result += ",!0";

        #icmp_unreach_echoed_dtsize = [8, 64, >64]

        echoed_dtsize = get_ip_element(ip:ret, element:"ip_len") - 20;
        if (echoed_dtsize == 64)
            reslt += ",64";
        else if (echoed_dtsize > 64)
            result += ",>64";
        else if (echoed_dtsize == 8)
            result += ",8";
        else
            result += "," + echoed_dtsize;

        # Original_data_echoed_with_the_UDP_Port_Unreachable_error_message
        # we bypass the ip + icmp_unreach and we get to our original packet!

        hl = get_ip_element(ip:ret, element:"ip_hl");
        echoed_ip_packet = substr(ret, hl*4+8);
        echoed_ip_packet_hl = get_ip_element(ip:echoed_ip_packet, element:"ip_hl");
        echoed_udp_packet = substr(echoed_ip_packet, echoed_ip_packet_hl*4);

        # icmp_unreach_reply_ttl = [>< decimal num]

        reply_ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ip_packet_ttl = get_ip_element(ip: ip_packet, element : "ip_ttl");
        echoed_ip_packet_ttl = get_ip_element(ip:echoed_ip_packet, element:"ip_ttl");
        real_ttl = reply_ttl + ip_packet_ttl - echoed_ip_packet_ttl ;

        if (real_ttl <= 32)
            result += ",<32";
        else if (real_ttl <= 60)
            result += ",<60";
        else if (real_ttl <= 64)
            result += ",<64";
        else if (real_ttl <= 128)
            result += ",<128";
        else
            result += ",<255";

        # Extracting checksums from echoed datagram
        # icmp_unreach_echoed_udp_cksum = [0, OK, BAD]

        echoed_udp_checksum = get_udp_element(udp: echoed_udp_packet, element:"uh_sum");
        udp_packet_checksum = get_udp_element(udp: udp_packet, element: "uh_sum");

        if (echoed_udp_checksum == udp_packet_checksum)
            result += ",OK";
        else if (echoed_udp_checksum == 0)
            result += ",0";
        else
            result += ",BAD";

        # icmp_unreach_echoed_ip_cksum  = [0, OK, BAD]

        echoed_ip_checksum = get_ip_element(ip:echoed_ip_packet, element:"ip_sum");

        # making a copy of the original udp_packet with updated ttl field
        # to the echoed_ip_packet's ttl and then extracting ip checksum
        # from udp_packet_copy

        ip_packet_copy = forge_ip_packet(ip_id  : IP_ID,
                            ip_p   : IPPROTO_UDP,
                            ip_off : IP_DF,
                            ip_src : this_host(),
                            ip_ttl : get_ip_element(ip:echoed_ip_packet, element:"ip_ttl"));
        udp_packet_copy =
            forge_udp_packet(
                                data     : crap(70),
                                ip       : ip_packet_copy,
                                uh_dport : dport,
                                uh_sport : 53
                             );

        ip_packet_copy_checksum = get_ip_element(ip:udp_packet_copy, element: "ip_sum");

        if (echoed_ip_checksum == ip_packet_copy_checksum)
            result += ",OK";
        else if (echoed_ip_checksum == 0)
            result += ",0";
        else
            result += ",BAD";

        # icmp_unreach_echoed_ip_id = [OK, FLIPPED]
        original_ip_id = substr(ip_packet, 4,5);
        echoed_ip_id = substr(echoed_ip_packet, 4,5);
        # flipp the two bytes
        flipped_original_ip_id = raw_string(substr(original_ip_id, 1), substr(original_ip_id, 0, 0));
        # end flipp

        if (original_ip_id == echoed_ip_id)
            result += ",OK";
        else if (original_ip_id == flipped_original_ip_id)
            result += ",FLIPPED";
        else
            result += ",BAD";

        # icmp_unreach_echoed_total_len = [>20, OK, <20]

        echoed_total_len = get_ip_element(ip:echoed_ip_packet, element: "ip_len");
        original_total_len = get_ip_element(ip:udp_packet, element: "ip_len");

        if (echoed_total_len == original_total_len)
            result += ",OK";
        else if (echoed_total_len == original_total_len - 20)
            result += ",<20";
        else if (echoed_total_len == original_total_len + 20)
            result += ",>20";
        else
            result += ",unexpected";

        # icmp_unreach_echoed_3bit_flags = [OK, FLIPPED]

        echoed_ip_frag_off = get_ip_element(ip:echoed_ip_packet, element: "ip_off");
        original_ip_frag_off = get_ip_element(ip:ip_packet, element: "ip_off");

        # flipp the two bytes

        flipped_original_ip_frag_off = raw_string(substr(original_ip_frag_off, 1), substr(original_ip_frag_off, 0, 0));

        #end flipp

        if (echoed_ip_frag_off == original_ip_frag_off)
            result += ",OK";
        else if (echoed_ip_frag_off == flipped_original_ip_frag_off)
            result += ",FLIPPED";
        else
            result += ",unexpected";
    } else {
        # For later use by other VTs
        set_kb_item( name:"ICMPv4/UDPPortUnreachable/failed", value:TRUE );
        result += "n,,,,,,,,,,";
    }

    return result;
}

#------------------------------------------------------------------------------

result =
    ModuleA() + "," +
    ModuleB() + "," +
    ModuleC() + "," +
    ModuleD() + "," +
    ModuleE();

# display(result, '\n');

fp = split(result, sep:",", keep:0);


best_score     = 0;
best_os        = make_array();
store_sections = FALSE;

if (passed) {

    section_title = "";

    foreach line (FINGERPRINTS) {

        if (section_title == "") {
            extract = split(line, sep:",", keep:0);
            section_title = extract[0];
            section_cpe = extract[1];
            continue;
        } else if (line == "") {
            section_title = "";
            continue;
        } else {

            ar = split(line, sep:",", keep:0);

            name = ar[0];
            score = 0;
            total = 0;

            for (i = 0; i < max_index(fp); ++i) {
                # skip unset value
                if (isnull(fp[i]) || fp[i] == "")
                    continue;

                total += 1;

                if (!isnull(ar[i+1]) && ar[i+1] != "" && ar[i+1] == fp[i])
                    score += 1;
            }

            if (total > 0)
                percentage = 100*score/total;

            if (percentage > best_score) {
                best_score = percentage;
                best_os = make_array(name, section_cpe);
                store_sections = FALSE;
            } else if (percentage == best_score) {
                # In case we have several matches, then just use the section title
                if (!store_sections) {
                    best_os = make_array(section_title, section_cpe);
                    store_sections = TRUE;
                } else {
                    best_os[section_title] = section_cpe;
                }
            }
        }
    }
}

if( best_score == 0 ) {
  best_os = "Unknown";
}

if( typeof( best_os ) == "array") {

  # Creating report before iterating later again as we want to report multiple detected OS within one single report
  report = '\n(' + best_score + '% confidence)\n';
  foreach ostitle( keys( best_os ) ) {
    report += '\n' + ostitle;
  }

  # Counter for later as we don't have a port registered for ICMP
  i = 0;

  foreach ostitle( keys( best_os ) ) {

    i++;
    set_kb_item( name:"Host/OS/ICMP", value:ostitle );
    set_kb_item( name:"Host/OS/ICMP/Confidence", value:best_score );

    if( "linux" >< tolower( report ) || "bsd" >< tolower( report ) || "mac os x" >< tolower( report ) ) {
      # Some systems not answering to ICMP are often identified as "HP JetDirect/Linux Kernel/Microsoft Windows"
      # so check here if this is the case and don't set the kb
      if( "windows" >!< tolower( report ) ) {
        runs_key = "unixoide";
      }
    }

    if( "windows" >< tolower( report ) ) {
      # Some systems not answering to ICMP are often identified as "HP JetDirect/Linux Kernel/Microsoft Windows"
      # so check here if this is the case and don't set the kb
      if( "linux" >!< tolower( report ) && "bsd" >!< tolower( report ) && "mac os x" >!< tolower( report ) ) {
        runs_key = "windows";
      }
    }

    # nb: Setting the runs_key to unixoide makes sure that we still schedule VTs using Host/runs_unixoide as a fallback
    if( ! runs_key ) runs_key = "unixoide";

    os_register_and_report( os:ostitle, cpe:best_os[ostitle], banner_type:"ICMP based OS fingerprint", desc:SCRIPT_DESC, port:i, proto:"icmp", runs_key:runs_key );
  }
} else {

  # No match found (best_score == 0 from above) so don't register the host detail here
  set_kb_item( name:"Host/OS/ICMP", value:best_os );
  set_kb_item( name:"Host/OS/ICMP/Confidence", value:best_score );
}

exit( 0 );
