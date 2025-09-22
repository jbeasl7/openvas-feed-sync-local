# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803378");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-1375", "CVE-2013-1371", "CVE-2013-0650", "CVE-2013-0646");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-04-18 15:45:01 +0530 (Thu, 18 Apr 2013)");
  script_name("Adobe AIR Multiple Vulnerabilities -01 (Apr 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52590");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58436");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58440");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-09.html");
  script_xref(name:"URL", value:"https://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe AIR Version prior to 3.6.0.6090 on Mac OS X.");
  script_tag(name:"insight", value:"Multiple flaws due to

  - Heap based overflow via unspecified vectors.

  - Integer overflow via unspecified vectors.

  - Use-after-free errors.");
  script_tag(name:"solution", value:"Upgrade to version 3.6.0.6090 or later.");
  script_tag(name:"summary", value:"Adobe AIR is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Air/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"3.6.0.6090"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.0.6090");
    security_message(port: 0, data: report);
    exit(0);
  }
}
