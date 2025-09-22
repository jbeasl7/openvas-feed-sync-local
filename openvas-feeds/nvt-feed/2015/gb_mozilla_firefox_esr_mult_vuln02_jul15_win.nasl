# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805909");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2015-2725", "CVE-2015-2727", "CVE-2015-2729", "CVE-2015-2731",
                "CVE-2015-2741");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2015-07-08 15:59:57 +0530 (Wed, 08 Jul 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-02 (Jul 2015) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple unspecified memory related errors.

  - An error within the 'AudioParamTimeline::AudioNodeInputValue' function in the
  Web Audio implementation.

  - An use-after-free error.

  - An overridable error allowing for skipping pinning checks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, obtain sensitive information, conduct
  man-in-the-middle attack and conduct denial-of-service attack.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 38.x before 38.1");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-59");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75541");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-67");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-63");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^38\.")
{
  if(version_is_less(version:vers, test_version:"38.1"))
  {
    report = 'Installed version: ' + vers +    '\n' +
             'Fixed version:     ' + "38.1" +   '\n';

    security_message(data:report);
    exit(0);
  }
}
