# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902949");
  script_version("2025-08-01T05:45:36+0000");
  script_cve_id("CVE-2012-3214", "CVE-2012-3217");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-02-13 11:28:37 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55977");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55993");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_fast_search_server_detect.nasl");
  script_mandatory_keys("microsoft/fast_search_server/smb-login/detected");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could run arbitrary code in the context of a user
  account with a restricted token.");

  script_tag(name:"affected", value:"Microsoft FAST Search Server 2010 for SharePoint Service Pack 1.");

  script_tag(name:"insight", value:"The flaws are due to the error in Oracle Outside In libraries, when
  used by the Advanced Filter Pack while parsing specially crafted files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-013.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!path = get_kb_item("microsoft/fast_search_server/smb-login/install_path"))
  exit(0);

dllPath = path + "bin";
dllVer = fetch_file_version(sysPath:dllPath, file_name:"Vseshr.dll");
if(!dllVer || dllVer !~ "^8\.")
  exit(0);

if(version_in_range(version:dllVer, test_version:"8.3.7.000", test_version2:"8.3.7.206")) {
  report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"8.3.7.000 - 8.3.7.206", install_path:dllPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
