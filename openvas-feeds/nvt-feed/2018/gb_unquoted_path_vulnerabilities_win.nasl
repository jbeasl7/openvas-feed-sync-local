# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107303");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-03-23 08:14:54 +0100 (Fri, 23 Mar 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 22:01:00 +0000 (Thu, 28 Oct 2021)");
  script_name("Microsoft Windows Unquoted Path Vulnerability (SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_gather_service_list_win.nasl");

  script_mandatory_keys("SMB/Windows/Arch", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2005-2936",
                "CVE-2007-5618",
                "CVE-2009-2761",
                "CVE-2012-4350",
                "CVE-2013-0513",
                "CVE-2013-1092",
                "CVE-2013-1609",
                "CVE-2013-1610",
                "CVE-2013-2151",
                "CVE-2013-2152",
                "CVE-2013-2176",
                "CVE-2013-2231",
                "CVE-2013-5011",
                "CVE-2013-6182",
                "CVE-2013-6773",
                "CVE-2014-0759",
                "CVE-2014-4634",
                "CVE-2014-5455",
                "CVE-2014-9646",
                "CVE-2015-0884",
                "CVE-2015-1484",
                "CVE-2015-2789",
                "CVE-2015-3987",
                "CVE-2015-4173",
                "CVE-2015-7866",
                "CVE-2015-8156",
                "CVE-2015-8988",
                "CVE-2016-15003",
                "CVE-2016-3161",
                "CVE-2016-4158",
                "CVE-2016-5793",
                "CVE-2016-5852",
                "CVE-2016-6803",
                "CVE-2016-6935",
                "CVE-2016-7165",
                "CVE-2016-8102",
                "CVE-2016-8225",
                "CVE-2016-8769",
                "CVE-2016-9356",
                "CVE-2017-1000475",
                "CVE-2017-12730",
                "CVE-2017-14019",
                "CVE-2017-14030",
                "CVE-2017-15383",
                "CVE-2017-3005",
                "CVE-2017-3141",
                "CVE-2017-3751",
                "CVE-2017-3756",
                "CVE-2017-3757",
                "CVE-2017-5873",
                "CVE-2017-6005",
                "CVE-2017-7180",
                "CVE-2017-9247",
                "CVE-2017-9644",
                "CVE-2018-0594",
                "CVE-2018-0595",
                "CVE-2018-11063",
                "CVE-2018-20341",
                "CVE-2018-2406",
                "CVE-2018-3668",
                "CVE-2018-3683",
                "CVE-2018-3684",
                "CVE-2018-3687",
                "CVE-2018-3688",
                "CVE-2018-5470",
                "CVE-2018-6016",
                "CVE-2018-6321",
                "CVE-2018-6384",
                "CVE-2019-11093",
                "CVE-2019-14599",
                "CVE-2019-14685",
                "CVE-2019-17658",
                "CVE-2019-20362",
                "CVE-2019-7201",
                "CVE-2019-7590",
                "CVE-2020-0507",
                "CVE-2020-0546",
                "CVE-2020-13884",
                "CVE-2020-15261",
                "CVE-2020-22809",
                "CVE-2020-28209",
                "CVE-2020-35152",
                "CVE-2020-5147",
                "CVE-2020-5569",
                "CVE-2020-7252",
                "CVE-2020-7316",
                "CVE-2020-7331",
                "CVE-2020-8326",
                "CVE-2020-9292",
                "CVE-2021-0112",
                "CVE-2021-21078",
                "CVE-2021-23197",
                "CVE-2021-23879",
                "CVE-2021-25269",
                "CVE-2021-27608",
                "CVE-2021-29218",
                "CVE-2021-33095",
                "CVE-2021-35230",
                "CVE-2021-35231",
                "CVE-2021-35469",
                "CVE-2021-37363",
                "CVE-2021-37364",
                "CVE-2021-42563",
                "CVE-2021-43454",
                "CVE-2021-43455",
                "CVE-2021-43456",
                "CVE-2021-43457",
                "CVE-2021-43458",
                "CVE-2021-43460",
                "CVE-2021-43463",
                "CVE-2021-45819",
                "CVE-2021-46443",
                "CVE-2022-2147",
                "CVE-2022-23909",
                "CVE-2022-25031",
                "CVE-2022-26634",
                "CVE-2022-27050",
                "CVE-2022-27052",
                "CVE-2022-27088",
                "CVE-2022-27089",
                "CVE-2022-27092",
                "CVE-2022-27094",
                "CVE-2022-27095",
                "CVE-2022-29320",
                "CVE-2022-31591",
                "CVE-2022-33035",
                "CVE-2022-35292",
                "CVE-2022-35899",
                "CVE-2022-37197",
                "CVE-2022-4429",
                "CVE-2022-44264",
                "CVE-2023-24671",
                "CVE-2023-26911",
                "CVE-2023-31747",
                "CVE-2023-3438",
                "CVE-2023-36658",
                "CVE-2023-37537",
                "CVE-2023-6631",
                "CVE-2023-7043",
                "CVE-2024-1618",
                "CVE-2024-25552",
                "CVE-2025-5191",
                "CVE-2025-39246"
               );

  script_xref(name:"URL", value:"https://web.archive.org/web/20201111194349/https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341");
  script_xref(name:"URL", value:"http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/");
  script_xref(name:"URL", value:"https://www.tecklyfe.com/remediation-microsoft-windows-unquoted-service-path-enumeration-vulnerability/");
  script_xref(name:"URL", value:"https://blogs.technet.microsoft.com/srd/2018/04/04/triaging-a-dll-planting-vulnerability");

  script_tag(name:"summary", value:"The script tries to detect Windows 'Uninstall' registry entries
  and 'Services' using an unquoted path containing at least one whitespace.");

  script_tag(name:"insight", value:"If the path contains spaces and is not surrounded by quotation
  marks, the Windows API has to guess where to find the referenced program. If e.g. a service is
  using the following unquoted path:

  C:\Program Files\Folder\service.exe

  then a start of the service would first try to run:

  C:\Program.exe

  and if not found:

  C:\Program Files\Folder\service.exe

  afterwards. In this example the behavior allows a local attacker with low privileges and write
  permissions on C:\ to place a malicious Program.exe which is then executed on a service/host
  restart or during the uninstallation of a software.

  NOTE: Currently only 'Services' using an unquoted path are reported as a vulnerability. The
  'Uninstall' vulnerability requires an Administrator / User to actively uninstall the affected
  software to trigger this vulnerability.");

  script_tag(name:"impact", value:"A local attacker could gain elevated privileges by inserting an
  executable file in the path of the affected service or uninstall entry.");

  script_tag(name:"affected", value:"Software installing an 'Uninstall' registry entry or 'Service'
  on Microsoft Windows using an unquoted path containing at least one whitespace.");

  script_tag(name:"solution", value:"Either put the listed vulnerable paths in quotation by manually
  using the onboard Registry editor or contact your vendor to get an update for the specified
  software that fixes this vulnerability.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");
include("misc_func.inc");

# function to check if there is a specific space outside of quotes
function unquoted_path_check(str) {
  local_var in_quotes, i, ch, next_ch, space_outside, str_length;

  in_quotes = FALSE;
  space_outside = FALSE;
  next_ch = "";
  str_length = strlen(str);

  # If the whole string is within quotes, we know its not vulnerable
  if (egrep(string:str, pattern:'^".*"$'))
    return FALSE;

  # If the string has no spaces, we know its not vulnerable
  if (!ereg(string:str, pattern:" "))
    return FALSE;

  # If the first .exe and its path is inside quotes, we know its not vulnerable
  if (egrep(string:str, pattern:"^" + '"' + "[a-zA-Z]:\\[^.:]*\.exe" + '"'))
    return FALSE;

  # If the first .exe and its path contain no space, we know its not vulnerable
  if (egrep(string:str, pattern: "^[a-zA-Z]:\\[^ .:]*\.exe"))
    return FALSE;

  for (i = 0; i < str_length; i++) {
    ch = substr(str, i, i);

    if (i < str_length){
      next_ch = substr(str, i+1,i+1);
    }

    if (ch == '"') {
      in_quotes = !in_quotes;  # toggle quote state
    }

    if (ch == ' ' && in_quotes == FALSE){
      space_outside = TRUE;
    }

    if (ch == ' ' && in_quotes == FALSE && (next_ch != '/' && next_ch != '-' && next_ch != ' ')) {
      return TRUE;
    } else if (ch == ' ' && in_quotes == FALSE && (next_ch == '/' || next_ch == '-' || next_ch == ' ')) {
      return FALSE;
    }

    if ((i+1) == str_length && space_outside == TRUE) {
      return TRUE;
    }

  }
  return FALSE;
}

if (FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM") {
  if (get_kb_item( "SMB/gather_service_list_win/error"))
    exit( 0 );

  if (!service_list = get_kb_item("SMB/gather_service_list_win/services"))
    exit( 0 );

  foreach service (split(service_list)) {
    value = eregmatch(string:service, pattern:"([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);([^;]*);");
    display_name = value[1];
    service_name = value[2];
    path_name = value[6];

    if (unquoted_path_check(str:path_name)) {
      services_report += display_name + "|" + service_name + "|" + path_name + '\n';
      SERVICES_VULN = TRUE;
    }
  }
} else {
  if (get_kb_item("win/lsc/disable_win_cmd_exec"))
    exit(0);

  ps_cmd = "Get-CimInstance -query 'SELECT DisplayName, Name, PathName FROM Win32_Service' | ForEach-Object { $_.DisplayName + '|' + $_.Name + '|' + $_.PathName }";
  services = powershell_cmd(cmd:ps_cmd);
  if (services) {

    services_list = split(services, keep:FALSE);

    foreach service(services_list) {

      service_split = split(service, sep:"|", keep:FALSE);
      path_name = service_split[2];

      if (unquoted_path_check(str:path_name)) {
        services_report += service + '\n';
        SERVICES_VULN = TRUE;
      }
    }
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if ("x86" >< os_arch) {
  cmd = "(get-childitem 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\').PSPath,((get-childitem 'Microsoft.PowerShell.Core\Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\').PSPath | % { Get-ChildItem $_ }).PSPath | ? {$_ -ne $NULL} | % { Get-ItemProperty $_} | select DisplayName, UninstallString, QuietUninstallString | %  {if($_.DisplayName){$($_.DisplayName -replace('[\0;]','')) + '|' + $($_.UninstallString -replace('[\0;]','')) + '|' + $($_.QuietUninstallString -replace('[\0;]','')) }} | sort";
} else if ("x64" >< os_arch) {
  cmd = "(get-childitem 'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\', 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\').PSPath,((get-childitem 'Microsoft.PowerShell.Core\Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\').PSPath | % { Get-ChildItem $_ }).PSPath | ? {$_ -ne $NULL} | % { Get-ItemProperty $_} | select DisplayName, UninstallString, QuietUninstallString | %  {if($_.DisplayName){$($_.DisplayName -replace('[\0;]','')) + '|' + $($_.UninstallString -replace('[\0;]','')) + '|' + $($_.QuietUninstallString -replace('[\0;]','')) }} | sort";
}

installed_software = powershell_cmd(cmd:cmd);
if (installed_software) {

  software_list = split( installed_software, keep:FALSE );

  foreach software(software_list) {

    software_split = split( software, sep:"|", keep:FALSE );
    display_name = software_split[0];
    uninstall_string = software_split[1];
    quiet_uninstall_string = software_split[2];

    if (uninstall_string) {
      if (unquoted_path_check(str:uninstall_string)) {
        uninstall_report += display_name + "|" + uninstall_string + '\n';
        UNINSTALL_VULN = TRUE;
      }
    }

    if (quiet_uninstall_string) {
      if (unquoted_path_check(str:quiet_uninstall_string)) {
        uninstall_report += display_name + "|" + quiet_uninstall_string + '\n';
        UNINSTALL_VULN = TRUE;
      }
    }
  }
}

if (SERVICES_VULN || UNINSTALL_VULN) {

  if (UNINSTALL_VULN) {
    report  = "The following 'Uninstall' registry entries are using an 'unquoted' path:";
    report += '\n\nDisplayName|Value\n';
    report += uninstall_report;
    log_message( port:0, data:report ); # nb: We don't want to report a vulnerability for now as an admin would need to actively uninstall a software to trigger this vulnerability.
  }

  if (SERVICES_VULN) {
    report  = "The following services are using an 'unquoted' service path:";
    report += '\n\nDisplayName|Name|PathName\n';
    report += services_report;
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
