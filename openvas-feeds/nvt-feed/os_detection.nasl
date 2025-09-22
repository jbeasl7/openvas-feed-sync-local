# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105937");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-02-19 11:19:54 +0100 (Fri, 19 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OS Detection Consolidation and Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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
                      "gb_android_adb_detect.nasl", "netbios_name_get.nasl",
                      "gb_nmap_os_detection.nasl", "os_fingerprint.nasl");
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

  script_xref(name:"URL", value:"https://forum.greenbone.net/c/vulnerability-tests/7");

  script_tag(name:"summary", value:"This script consolidates the OS information detected by several
  VTs and tries to find the best matching OS.

  Furthermore it reports all previously collected information leading to this best matching OS. It
  also reports possible additional information which might help to improve the OS detection.

  If any of this information is wrong or could be improved please consider to report these to the
  referenced community forum.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

found_best = FALSE;
found_os = ""; # nb: To make openvas-nasl-lint happy...

# nb: We only want to check the CPE entries
oid_list = os_get_cpe_src_list();

foreach oid( oid_list ) {
  os = get_kb_list( "HostDetails/NVT/" + oid + "/OS" );
  if( ! isnull( os ) ) {
    res = make_list( os );
    foreach entry( res ) {
      # Discard non CPE entries
      if( "cpe:/" >!< entry )
        continue;

      desc = get_kb_item( "HostDetails/NVT/" + oid );

      if( ! found_best ) {

        os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
        if( ! os_reports )
          continue;

        # Use keys to be able to extract the port and proto later
        foreach key( keys( os_reports ) ) {

          # We need the port and proto for the host_runs kb entry later
          tmp   = split( key, sep:"/", keep:FALSE );
          port  = tmp[3];
          proto = tmp[4];

          # There might be multiple keys/entries for the same port (e.g. http)
          # so using get_kb_list instead() of get_kb_item() here.
          os_reports = get_kb_list( key );
          foreach os_report( os_reports ) {

            # TODO: This is currently only reporting the very first entry of multiple OS detections from the same Detection-VT (e.g. http).
            # We need to find a way to differ in such cases, maybe via a "found_best" list instead of a single variable? In addition there
            # might be additional cases where one HTTP Detection is more detailed then another one.
            if( ! found_best ) {
              report = 'Best matching OS:\n\n' + os_report;
              found_best = TRUE;
              best_match_oid = oid;
              best_match_desc = desc;
              best_match_report = os_report; # To avoid that it will be added to the "Other OS detections" text (see the checks down below)

              # TODO: os_register_and_report() should save this information (together with the CPE) into an own KB entry so that
              # we can use it directly without extracting it from the os_detection_report().
              _best_match_txt = egrep( string:os_report, pattern:'^OS: *[^\r\n]+', icase:FALSE );
              _best_match_txt = chomp( _best_match_txt );
              if( _best_match_txt ) {
                _best_match_txt = eregmatch( string:_best_match_txt, pattern:"OS: *(.+)", icase:FALSE );
                if( _best_match_txt[1] ) {
                  best_match_txt = _best_match_txt[1];
                  _best_match_txt_vers = egrep( string:os_report, pattern:'^Version: *[^\r\n]+', icase:FALSE );
                  _best_match_txt_vers = chomp( _best_match_txt_vers );
                  if( _best_match_txt_vers && _best_match_txt_vers !~ "unknown" ) {
                    _best_match_txt_vers = eregmatch( string:_best_match_txt_vers, pattern:"Version: *(.+)", icase:FALSE );
                    # nb: Avoid adding the version number if it was already included in the "OS:" part (shouldn't happen but just to be sure...)
                    if( _best_match_txt_vers[1] && _best_match_txt_vers[1] >!< best_match_txt )
                      best_match_txt += " " + _best_match_txt_vers[1];
                  }
                }
              } else {
                best_match_txt = "N/A";
              }

              _best_match_cpe = egrep( string:os_report, pattern:'^CPE: *[^\r\n]+', icase:FALSE );
              _best_match_cpe = chomp( _best_match_cpe );
              if( _best_match_cpe ) {
                _best_match_cpe = eregmatch( string:_best_match_cpe, pattern:"CPE: *(.+)", icase:FALSE );
                if( _best_match_cpe[1] )
                  best_match_cpe = _best_match_cpe[1];
              } else {
                best_match_cpe = "N/A";
              }

              host_runs_list = get_kb_list( "os_detection_report/host_runs/" + oid + "/" + port + "/" + proto );

              # We could have multiple host_runs entries on the same port (e.g. http)
              # Choose the first match here
              foreach host_runs( host_runs_list ) {
                if( host_runs == "unixoide" ) {
                  set_key = "Host/runs_unixoide";
                } else if( host_runs == "windows" ) {
                  set_key = "Host/runs_windows";
                } else {
                  # This makes sure that we still scheduling VTs using Host/runs_unixoide as a fallback
                  set_key = "Host/runs_unixoide";
                }
                if( ! get_kb_item( set_key ) ) {
                  set_kb_item( name:set_key, value:TRUE );
                  report += '\nSetting key "' + set_key + '" based on this information';
                }
              }
            } else {
              if( os_report >!< found_os && os_report >!< best_match_report )
                found_os += os_report + '\n\n';
            }
          }
        }
      } else {
        os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
        foreach os_report( os_reports ) {
          if( os_report >!< found_os && os_report >!< best_match_report )
            found_os += os_report + '\n\n';
        }
      }
    }
  }
}

if( ! found_best ) {
  report += "No Best matching OS identified. Please see the VT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
  report += "for possible ways to identify this OS.";
  # nb: Setting the runs_key to unixoide makes sure that we still schedule VTs using Host/runs_unixoide as a fallback
  set_kb_item( name:"Host/runs_unixoide", value:TRUE );
} else {

  # TBD: Move into host_details.nasl?
  detail = best_match_oid + ";" + best_match_desc;
  set_kb_item( name:"HostDetails/OS/BestMatchCPE", value:best_match_cpe );
  set_kb_item( name:"HostDetails/OS/BestMatchCPE/Details", value:detail );
  set_kb_item( name:"HostDetails/OS/BestMatchTXT", value:best_match_txt );
  set_kb_item( name:"HostDetails/OS/BestMatchTXT/Details", value:detail );

  # Store link between os_detection.nasl and gb_os_eol.nasl
  # nb: We don't use the host_details.inc functions in both so we need to call this directly.
  register_host_detail( name:"OS-Detection", value:best_match_cpe );
  register_host_detail( name:best_match_cpe, value:"general/tcp" ); # the port:0 from below
  register_host_detail( name:"port", value:"general/tcp" ); # the port:0 from below
}

if( found_os )
  report += '\n\nOther OS detections (in order of reliability):\n\n' + found_os;

log_message( port:0, data:report );

exit( 0 );
