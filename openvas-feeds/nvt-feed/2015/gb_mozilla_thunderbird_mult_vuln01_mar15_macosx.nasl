# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805480");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-0836", "CVE-2015-0833", "CVE-2015-0831", "CVE-2015-0827",
                "CVE-2015-0822");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-03-03 16:09:47 +0530 (Tue, 03 Mar 2015)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 (Mar 2015) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

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

  script_tag(name:"affected", value:"Mozilla Thunderbird before version 31.5
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  31.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72756");
  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3174");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"31.5"))
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     31.5\n';
  security_message(data:report);
  exit(0);
}
