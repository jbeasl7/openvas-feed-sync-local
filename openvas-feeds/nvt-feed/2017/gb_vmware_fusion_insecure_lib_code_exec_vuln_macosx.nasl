# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809792");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-1666");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-02-01 11:12:47 +0530 (Wed, 01 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Fusion Insecure 'tpfc.dll' Code Execution Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"VMware Fusion is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to loading of insecure
  'tpfc.dll' library in thinprint.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to execute arbitrary code with the privileges of the user running
  the affected application.");

  script_tag(name:"affected", value:"VMware Fusion 4.x before 4.1.2 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VMware Fusion version
  4.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://cve.circl.lu/cve/CVE-2012-1666");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55421");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vmware_fusion_detect_macosx.nasl");
  script_mandatory_keys("VMware/Fusion/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^4\.")
{
  if(version_is_less(version:vmwareVer, test_version:"4.1.2"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"4.1.2");
    security_message(data:report);
    exit(0);
  }
}
