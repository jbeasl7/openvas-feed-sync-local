# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803835");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-3348");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-07-25 17:56:29 +0530 (Thu, 25 Jul 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities-01 (Jul 2013) - Mac OS X");
  script_tag(name:"summary", value:"Adobe Shockwave player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 12.0.3.133 or later.");
  script_tag(name:"insight", value:"Flaw is due to an error when parsing dir files");
  script_tag(name:"affected", value:"Adobe Shockwave Player before 12.0.3.133 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code on the target system and corrupt system memory.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61040");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/MacOSX/Version");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Shockwave/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"12.0.3.133"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.3.133");
    security_message(port: 0, data: report);
    exit(0);
  }
}

