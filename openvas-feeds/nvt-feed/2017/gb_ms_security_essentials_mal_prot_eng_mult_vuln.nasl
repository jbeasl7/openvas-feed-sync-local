# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811068");
  script_version("2025-08-05T05:45:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-8535", "CVE-2017-8536", "CVE-2017-8537", "CVE-2017-8538",
                "CVE-2017-8539", "CVE-2017-8540", "CVE-2017-8541", "CVE-2017-8542");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-06-02 09:40:39 +0530 (Fri, 02 Jun 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Malware Protection Engine on Security Essentials Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Updates released for Microsoft Malware
  Protection Engine dated 05-25-2017");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple errors when the Microsoft Malware Protection Engine does not properly
    scan a specially crafted file, leading to a scan timeout.

  - Multiple errors when the Microsoft Malware Protection Engine does not properly scan a
    specially crafted file, leading to memory corruption.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the security context of the LocalSystem account
  and take control of the system. Also an attacker can lead to denial of service
  preventing the Microsoft Malware Protection Engine from monitoring affected
  systems until the service is restarted.");

  script_tag(name:"affected", value:"Microsoft Security Essentials.");

  script_tag(name:"solution", value:"Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8535");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98708");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98705");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98704");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98710");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98707");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8536");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8537");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8538");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8539");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8540");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8541");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8542");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl",
  "gb_ms_security_essentials_smb_login_detect.nasl");

  script_mandatory_keys("SMB/WindowsVersion", "microsoft/security_essentials/mpe_version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

mpe_version = get_kb_item("microsoft/security_essentials/mpe_version");
if(!mpe_version)
  exit(0);

##Last version of the Microsoft Malware Protection Engine affected by this vulnerability Version 1.1.13701.0
##First version of the Microsoft Malware Protection Engine with this vulnerability addressed 1.1.13704.0
if(version_is_less(version:mpe_version, test_version:"1.1.13704.0"))
{
   report = 'Installed version : ' + mpe_version + '\n' +
            'Vulnerable range: Less than 1.1.13704.0';
   security_message(data:report);
   exit(0);
}
exit(0);