# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816865");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2020-1002");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-21 19:21:00 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:39:55 +0530 (Wed, 15 Apr 2020)");
  script_name("Microsoft Security Essentials Elevation of Privilege Vulnerability (Apr 2020)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Updates released for Microsoft Security
  Essentials Protection Engine dated 23-09-2019");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target
  host.");

  script_tag(name:"insight", value:"The flaw exists when the MpSigStub.exe for Defender
  allows file deletion in arbitrary locations.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run a specially crafted command that could exploit the vulnerability and delete
  protected files on an affected system once MpSigStub.exe ran again.");

  script_tag(name:"affected", value:"Microsoft Security Essentials.");

  script_tag(name:"solution", value:"Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl",
  "gb_ms_security_essentials_smb_login_detect.nasl");

  script_mandatory_keys("SMB/WindowsVersion", "microsoft/security_essentials/mpe_version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

mpe_version = get_kb_item("microsoft/security_essentials/mpe_version");
if(!mpe_version)
  exit(0);

##First version of the Microsoft Malware Protection Engine with this vulnerability addressed 1.1.16638.0
if(version_is_less(version:mpe_version, test_version:"1.1.16638.0"))
{
  report = report_fixed_ver(installed_version:mpe_version, fixed_version: "1.1.16638.0 or higher");
  security_message(data:report);
  exit(0);
}
exit(0);