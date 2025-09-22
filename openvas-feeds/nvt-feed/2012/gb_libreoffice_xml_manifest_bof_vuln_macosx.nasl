# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803087");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-2665");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-12-24 17:40:15 +0530 (Mon, 24 Dec 2012)");
  script_name("LibreOffice XML Manifest Handling Buffer Overflow Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50142/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54769");
  script_xref(name:"URL", value:"http://www.libreoffice.org/advisories/CVE-2012-2665/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Version");
  script_tag(name:"insight", value:"Multiple heap-based buffer overflows in the XML manifest encryption tag
  parsing functionality allows attacker to crash the application via crafted
  Open Document Tex (.odt) file.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.5.5 or later.");
  script_tag(name:"summary", value:"LibreOffice is prone to buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service condition or execute arbitrary code.");
  script_tag(name:"affected", value:"LibreOffice version before 3.5.5 on Mac OS X");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

libreVer = get_kb_item("LibreOffice/MacOSX/Version");
if(!libreVer){
  exit(0);
}

if(version_is_less(version: libreVer, test_version:"3.5.5")){
  report = report_fixed_ver(installed_version:libreVer, fixed_version:"3.5.5");
  security_message(port:0, data:report);
}
