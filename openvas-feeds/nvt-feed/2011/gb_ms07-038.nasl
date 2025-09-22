# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801717");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-3038");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Microsoft Windows Vista Teredo Interface Firewall Bypass Vulnerability");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Jul/1018354.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24779");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-038");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to bypass firewall settings
  and possibly obtain sensitive information about the system.");

  script_tag(name:"affected", value:"Microsoft Windows Vista.");

  script_tag(name:"insight", value:"The flaw is due to an error in the handling of the Teredo transport
  mechanism resulting in network traffic being handled incorrectly though the
  Teredo interface. This may result in certain firewall rules being bypassed.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-038.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"935807") == 0){
  exit(0);
}

dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
   exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\drivers\tunnel.sys");

dllVer = GetVer(file:file, share:share);
if(dllVer)
{
  if(hotfix_check_sp(winVista:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6000.16501")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6000.16501");
          security_message(port: 0, data: report);
    }
         exit(0);
  }
}
