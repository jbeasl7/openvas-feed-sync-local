# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107306");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-04-26 15:23:05 +0100 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"10.0");
  script_name("Orangeworm Kwampirs Trojan Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Malware");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_gather_service_list_win.nasl");

  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia");
  script_xref(name:"URL", value:"http://www.virusresearch.org/kwampirs-trojan-removal/");

  script_tag(name:"summary", value:"The script tries to detect the Orangeworm Kwampirs Trojan via
  various known Indicators of Compromise (IOC).");

  script_tag(name:"insight", value:"The Orangeworm group is using a repurposed Trojan called
  Kwampirs to set up persistent remote access after they infiltrate victim organizations. Kwampirs
  is not especially stealthy and can be detected using indicators of compromise and activity on
  the target system. The Trojan evades hash-based detection by inserting a random string in its
  main executable so its hash is different on each system. However, Kwampirs uses consistent
  services names, configuration files, and similar payload DLLs on the target machine that can be
  used to detect it.");

  script_tag(name:"impact", value:"Trojan.Kwampirs is a Trojan horse that may open a back door on
  the compromised computer. It may also download potentially malicious files.");

  script_tag(name:"affected", value:"All Windows Systems.");

  script_tag(name:"solution", value:"A whole cleanup of the infected system is recommended.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM"){
  if(get_kb_item("SMB/gather_service_list_win/error"))
    exit(0);

  if(!service_list = get_kb_item("SMB/gather_service_list_win/services"))
    exit(0);

  foreach service (split(service_list)){
    value = eregmatch(string:service, pattern:"(.*);(.*);(.*);(.*);(.*);(.*);");
    display_name = value[1];
    service_name = value[2];
    path_name = value[6];

    indicators = 0;
    if("WmiApSrvEx" >< service_name) indicators++;
    if("WMI Performance Adapter Extension" >< display_name) indicators++;
    if("ControlTrace -Embedding -k" >< path_name) indicators++;
    if(indicators > 1){
      services_report += display_name + "|" + service_name + "|" + path_name + '\n';
      SERVICES_VULN = TRUE;
    }
  }
}else{
  service_list = powershell_cmd(cmd:"Get-CimInstance -ClassName Win32_Service | ForEach-Object { $_.DisplayName + '|' + $_.Name + '|' + $_.PathName }");
  if(!service_list)
    exit(0);

  foreach service (split(service_list)){
    value = eregmatch(string:service, pattern:"(.*)|(.*)|(.*)");
    display_name = value[1];
    service_name = value[2];
    path_name = value[3];

    indicators = 0;
    if("WmiApSrvEx" >< service_name) indicators++;
    if("WMI Performance Adapter Extension" >< display_name) indicators++;
    if("ControlTrace -Embedding -k" >< path_name) indicators++;
    if(indicators > 1){
      services_report += service + '\n';
      SERVICES_VULN = TRUE;
    }
  }
}

if(SERVICES_VULN){
  report = "Trojan.Kwampirs, a backdoor Trojan that provides attackers with remote access to this computer, has been found based on the following IOCs:";
  report += '\n\nDisplayName|Name|PathName\n';
  report += services_report;
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
