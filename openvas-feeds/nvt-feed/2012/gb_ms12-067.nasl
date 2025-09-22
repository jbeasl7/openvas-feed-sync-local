# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903042");
  script_version("2025-08-01T05:45:36+0000");
  script_cve_id("CVE-2012-1766", "CVE-2012-1767", "CVE-2012-1768", "CVE-2012-1769",
                "CVE-2012-1770", "CVE-2012-1771", "CVE-2012-1772", "CVE-2012-1773",
                "CVE-2012-3106", "CVE-2012-3107", "CVE-2012-3108", "CVE-2012-3109",
                "CVE-2012-3110");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-10-10 11:39:34 +0530 (Wed, 10 Oct 2012)");
  script_name("Microsoft FAST Search Server 2010 for SharePoint RCE Vulnerabilities (2742321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_fast_search_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/fast_search_server/smb-login/detected");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54504");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54531");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54536");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54543");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54546");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54548");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54550");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54554");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-067");

  script_tag(name:"impact", value:"Successful exploitation could run arbitrary code in the context of a user
  account with a restricted token.");

  script_tag(name:"affected", value:"Microsoft FAST Search Server 2010 for SharePoint Service Pack 1.");

  script_tag(name:"insight", value:"The flaws are due to the error in Oracle Outside In libraries, when
  used by the Advanced Filter Pack while parsing specially crafted files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-067.");

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
file_name = "microsoft.sharepoint.search.extended.administration.dll";
dllVer = fetch_file_version(sysPath:dllPath, file_name:file_name);
if(!dllVer || dllVer !~ "^14\.")
  exit(0);

if(version_in_range(version:dllVer, test_version:"14.0.329.0", test_version2:"14.0.334.10")) {
  report = report_fixed_ver(installed_version:dllVer, file_checked:dllPath + file_name, vulnerable_range:"14.0.329.0 - 14.0.334.10");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
