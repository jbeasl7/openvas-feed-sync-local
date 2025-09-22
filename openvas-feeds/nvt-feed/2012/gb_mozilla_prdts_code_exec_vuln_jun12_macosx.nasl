# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802875");
  script_version("2024-02-22T14:37:29+0000");
  script_cve_id("CVE-2011-3671");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-06-20 13:43:30 +0530 (Wed, 20 Jun 2012)");
  script_name("Mozilla Products 'nsHTMLSelectElement' Remote Code Execution Vulnerability - Mac OS X");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47302");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54080");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027183");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the browser.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.6,
  Thunderbird version 5.0 through 8.0,
  Mozilla Firefox version 4.x through 8.0 on Mac OS X.");
  script_tag(name:"insight", value:"A use-after-free error exists in 'nsHTMLSelectElement' when the parent node
  of the element is no longer active.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 9.0 or later, upgrade to SeaMonkey version to 2.6 or later,
  upgrade to Thunderbird version to 9.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"8.0"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 8.0");
    security_message(port:0, data:report);
    exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.6"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.6");
    security_message(port:0, data:report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"5.0", test_version2:"8.0"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"5.0 - 8.0");
    security_message(port:0, data:report);
    exit(0);
  }
}
