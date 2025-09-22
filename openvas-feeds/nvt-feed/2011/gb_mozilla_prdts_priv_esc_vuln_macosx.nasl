# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802512");
  script_version("2023-07-14T16:09:26+0000");
  script_cve_id("CVE-2011-3647");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-14 11:44:10 +0530 (Mon, 14 Nov 2011)");
  script_name("Mozilla Products Privilege Escalation Vulnerability (MFSA2011-46) - Mac OS X");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-46/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50589");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");

  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"insight", value:"An error exists in JSSubScriptLoader, which fails to handle
  XPCNativeWrappers during calls to the loadSubScript method in an add-on.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain privileges via
  a crafted web site that leverages certain unwrapping behavior.");

  script_tag(name:"affected", value:"- Mozilla Thunderbird version prior to 3.1.16

  - Mozilla Firefox version prior to 3.6.24");

  script_tag(name:"solution", value:"- Update Mozilla Firefox to version 3.6.24 or later

  - Update Mozilla Thunderbird to version to 3.1.16 or later");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"3.6.24")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.24");
    security_message(port:0, data:report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"3.1.16")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.16");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
