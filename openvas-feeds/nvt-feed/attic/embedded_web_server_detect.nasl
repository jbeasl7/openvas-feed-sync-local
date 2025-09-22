# SPDX-FileCopyrightText: 2006 TNS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19689");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Embedded Web Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 TNS");
  script_family("Service detection");

  script_tag(name:"summary", value:"This plugin determines if the remote web server is an embedded
  service (without any user-supplied CGIs).

  This VT has been deprecated because the used approach isn't valid / useful for modern environments
  anymore.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# nb: The info below is kept for history reasons:
# - This VT had checked the following and have set the remote system as "embedded" accordingly:
#   - The "Server" banner via ^[Ss]erver\s*:\s*(CUPS|MiniServ|AppleShareIP|Embedded Web Server|Embedded HTTPD|IP_SHARER|Ipswitch-IMail|MACOS_Personal_Websharing|NetCache appliance|ZyXEL-RomPager|cisco-IOS|u-Server|eMule|Allegro-Software-RomPager|RomPager|Desktop On-Call|D-Link|4D_WebStar|IPC@CHIP|Citrix Web PN Server|SonicWALL|Micro-Web|gSOAP|CompaqHTTPServer/|BBC [0-9.]+; .*[cC]oda)
#   - port == 901
#   - The "Server" banner via ^Webserver:$
# - Furthermore the following VTs had also marked a system as "embedded":
#   - cobalt_web_admin_server.nasl
#   - imss_detect.nasl
#   - clearswift_mimesweeper_smtp_detect.nasl
#   - sun_cobalt_adaptive_firewall_detect.nasl
#   - interspect_detect.nasl
#   - xedus_detect.nasl
#   - DDI_Cabletron_Web_View.nasl
#   - securenet_provider_detect.nasl
#   - intrushield_console_detect.nasl
#   - websense_detect.nasl
#   - tmcm_detect.nasl
#   - cisco_ids_manager_detect.nasl
#   - iwss_detect.nasl
#   - sitescope_management_server.nasl
#   - raptor_detect.nasl
