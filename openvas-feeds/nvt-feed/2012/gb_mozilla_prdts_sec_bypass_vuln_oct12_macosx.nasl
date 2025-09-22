# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802992");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-4192", "CVE-2012-4193");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-10-15 17:11:30 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Firefox Security Bypass Vulnerabilities (Oct 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55889");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-89.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass the Same Origin Policy
  and read the properties of a Location object via a crafted web site.");
  script_tag(name:"affected", value:"Mozilla Firefox versions before 16.0.1 on Mac OS X");
  script_tag(name:"insight", value:"Security wrappers are unwrapped without doing a security check in
  defaultValue(). This can allow for improper access to the Location object.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 16.0.1 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"16.0.1"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"16.0.1");
    security_message(port:0, data:report);
    exit(0);
  }
}
