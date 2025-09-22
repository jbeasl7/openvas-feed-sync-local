# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801705");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-13 17:08:42 +0100 (Thu, 13 Jan 2011)");
  script_cve_id("CVE-2008-0084");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows TCP/IP Denial of Service Vulnerability (946456)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Feb/1019383.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27634");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-004");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation leads to stop and automatically restart a vulnerable
  system via a specially crafted packet.");

  script_tag(name:"affected", value:"Microsoft Windows Vista.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in the 'TCP/IP' processing of
  packets received from DHCP (Dynamic Host Configuration Protocol) servers.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-004.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"946456") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\tcpip.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16627")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6000.16627");
      security_message(port: 0, data: report);
  }
  exit(0);
}
