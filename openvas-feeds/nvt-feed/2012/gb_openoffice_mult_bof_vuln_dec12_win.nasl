# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803083");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2012-1149", "CVE-2012-2665");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-12-24 15:26:59 +0530 (Mon, 24 Dec 2012)");
  script_name("OpenOffice Multiple Buffer Overflow Vulnerabilities (Dec 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46992/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54769");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50438/");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027068");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1027332");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2012-2665.html");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2012-1149.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"insight", value:"- An integer overflow error in the vclmi.dll module when allocating memory
    for an embedded image object.

  - Multiple heap-based buffer overflows in the XML manifest encryption tag
    parsing functionality allows attacker to crash the application via crafted
    Open Document Tex (.odt) file.");
  script_tag(name:"solution", value:"Upgrade to OpenOffice version 3.4.1 or later.");
  script_tag(name:"summary", value:"OpenOffice is prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service condition or execute arbitrary code.");
  script_tag(name:"affected", value:"OpenOffice version before 3.4.1 on windows");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openoffice.org/download/");
  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("OpenOffice/Win/Ver");
if(!officeVer){
  exit(0);
}

## (Display Version comes as 3.41.9593)
if(version_is_less(version: officeVer, test_version:"3.41.9593")){
  report = report_fixed_ver(installed_version:officeVer, fixed_version:"3.41.9593");
  security_message(port:0, data:report);
}
