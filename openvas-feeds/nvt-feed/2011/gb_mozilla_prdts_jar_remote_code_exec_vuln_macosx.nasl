# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902777");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2011-3666");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-12-22 13:17:34 +0530 (Thu, 22 Dec 2011)");
  script_name("Mozilla Products jar Files Remote Code Execution Vulnerability - Mac OS X");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51139");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-59.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in
  the context of the user running an affected application.");
  script_tag(name:"affected", value:"Thunderbird version prior to 3.1.17
  Mozilla Firefox version prior to 3.6.25");
  script_tag(name:"insight", value:"The flaw is due to not considering '.jar' files to be executable files
  which allows remote attackers to bypass intended access restrictions via a
  crafted file.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.25 or later, Upgrade to Thunderbird version to 3.1.17 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.25"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.25");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.1.17")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.17");
    security_message(port: 0, data: report);
  }
}
