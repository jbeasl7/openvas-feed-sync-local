# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805477");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-0836", "CVE-2015-0833", "CVE-2015-0831", "CVE-2015-0827",
                "CVE-2015-0822");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-03-03 15:35:20 +0530 (Tue, 03 Mar 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 (Mar 2015) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Some unspecified vulnerabilities in the browser engine.

  - Multiple untrusted search path vulnerabilities in updater.exe.

  - Use-after-free error in the 'IDBDatabase::CreateObjectStore' function in
  dom/indexedDB/IDBDatabase.cpp script.

  - Heap-based buffer overflow in the 'mozilla::gfx::CopyRect' and
  'nsTransformedTextRun::SetCapitalization' functions.

  - Flaw in the autocomplete feature for forms.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, bypass certain security
  restrictions, cause a denial of service, execute arbitrary code and local
  privilege escalation.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 31.x before 31.5 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 31.5
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72756");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-26");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^31\.")
{
  if((version_in_range(version:vers, test_version:"31.0", test_version2:"31.4")))
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     31.5\n';
    security_message(data:report);
    exit(0);
  }
}
