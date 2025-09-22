# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810744");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-2340", "CVE-2015-2339", "CVE-2015-2338", "CVE-2015-2337",
                "CVE-2015-2336", "CVE-2012-0897");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-04-07 17:06:57 +0530 (Fri, 07 Apr 2017)");
  script_name("VMware Workstation Code Execution And DoS Vulnerabilities (Apr 2017) - Windows");

  script_tag(name:"summary", value:"VMware Workstation Player is prone to code execution and denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to error in the
  'TPView.dll' and 'TPInt.dll' which incorrectly handles memory allocation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"VMware Workstation Player 10.x before
  10.0.6 and 11.x before 11.1.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Workstation Player version
  10.0.6 or 11.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75092");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51426");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^10\.")
{
  if(version_is_less(version:vmwareVer, test_version:"10.0.6"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"10.0.6");
    security_message(data:report );
    exit(0);
  }
}

else if(vmwareVer =~ "^11\.")
{
  if(version_is_less(version:vmwareVer, test_version:"11.1.1"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"11.1.1");
    security_message(data:report );
    exit(0);
  }
}

exit(99);