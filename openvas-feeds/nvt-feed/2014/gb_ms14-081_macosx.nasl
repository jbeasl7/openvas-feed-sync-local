# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805029");
  script_version("2024-02-28T05:05:37+0000");
  script_cve_id("CVE-2014-6356", "CVE-2014-6357");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-12-10 13:24:58 +0530 (Wed, 10 Dec 2014)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (3017301) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-081.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An invalid indexing error when parsing Office files can be exploited to
    execute arbitrary code via a specially crafted Office file.

  - A use-after-free error when parsing Office files can be exploited to execute
    arbitrary code via a specially crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute the arbitrary code, cause memory corruption and
  compromise the system.");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3018888");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71470");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-081");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");

  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");

if(!offVer || offVer !~ "^14\."){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.4.6"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
