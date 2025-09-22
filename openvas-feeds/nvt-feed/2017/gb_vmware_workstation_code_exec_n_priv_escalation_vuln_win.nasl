# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809796");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2012-3569", "CVE-2012-5458", "CVE-2012-5459");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-02-07 17:19:44 +0530 (Tue, 07 Feb 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation Code Execution And Privilege Escalation Vulnerabilities (VMSA-2012-0015) - Windows");

  script_tag(name:"summary", value:"VMware Workstation is prone to code execution and privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Insecure process threads permissions.

  - Format string error in VMware OVF Tool.

  - Untrusted search path error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code or cause denial-of-service conditions and also gain
  elevated privileges on the target host.");

  script_tag(name:"affected", value:"VMware Workstation version 8.x before
  8.0.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Workstation version
  8.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/120101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56470");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56468");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0015.html");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Workstation/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^8\.")
{
  if(version_is_less(version:vmwareVer, test_version:"8.0.5"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"8.0.5");
    security_message(data:report);
    exit(0);
  }
}
