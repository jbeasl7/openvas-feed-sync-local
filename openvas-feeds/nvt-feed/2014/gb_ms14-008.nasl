# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:microsoft_forefront_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903430");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2014-0294");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-02-12 10:41:31 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft Forefront Protection For Exchange RCE Vulnerability (2927022)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-008.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error when parsing mail content.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to run arbitrary code via a
  specially crafted email message and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft Forefront Protection 2010 for Exchange Server.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2927022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65397");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-008");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_forefront_protection_detect.nasl");
  script_mandatory_keys("Microsoft/ForefrontServerProtection/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!ediVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange") &&
   !registry_key_exists(key:"SOFTWARE\Microsoft\ExchangeServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Exchange\";

exchangePath = registry_get_sz(key: key, item:"InstallLocation");

## exit if not get install path
if(!exchangePath){
  exit(0);
}

exchangePath = exchangePath + "\TransportRoles\agents\FSEAgent\bin";

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Microsoft.fss.antispam.dll");
if(!exeVer){
  exit(0);
}

if(version_is_less(version:exeVer, test_version:"11.0.747.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
