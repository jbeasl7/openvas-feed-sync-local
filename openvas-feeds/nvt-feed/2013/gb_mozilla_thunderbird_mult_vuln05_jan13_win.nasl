# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803177");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-0760", "CVE-2013-0770");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-16 17:04:59 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-05 (Jan 2013) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57199");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57207");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027957");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.");
  script_tag(name:"affected", value:"Thunderbird version before 17.0.2 on Windows");
  script_tag(name:"insight", value:"- An error within the 'CharDistributionAnalysis::HandleOneChar()' can be
    exploited to cause a buffer overflow.

  - Unspecified error in the browser engine can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version to 17.0.2 or later");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/Win/Ver");
if(!vers)
  exit(0);

if(version_is_less(version:vers, test_version:"17.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.0.2");
  security_message(port: 0, data: report);
  exit(0);
}
