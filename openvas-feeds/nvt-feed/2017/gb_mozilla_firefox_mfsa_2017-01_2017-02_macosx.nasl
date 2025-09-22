# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809876");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378",
                "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5390", "CVE-2017-5389",
                "CVE-2017-5396", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383",
                "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5374",
                "CVE-2017-5391", "CVE-2017-5388", "CVE-2017-5393", "CVE-2017-5373",
                "CVE-2017-5387");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:35:00 +0000 (Thu, 02 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-01-27 12:08:46 +0530 (Fri, 27 Jan 2017)");
  script_name("Mozilla Firefox Security Advisories (MFSA2017-01, MFSA2017-02) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Excessive JIT code allocation allows bypass of ASLR and DEP.

  - Use-after-free in XSL.

  - Memory corruption with transforms to create gradients in Skia.

  - Pointer and frame data leakage of Javascript objects.

  - Use-after-free in Web Animations.

  - Potential use-after-free during DOM manipulations.

  - Insecure communication methods in Developer Tools JSON viewer.

  - WebExtensions can install additional add-ons via modified host requests.

  - Use-after-free with Media Decoder.

  - Certificate Viewer exporting can be used to navigate and save to arbitrary filesystem locations.

  - Feed preview can expose privileged content errors and exceptions.

  - Location bar spoofing with unicode characters.

  - Information disclosure via Proxy Auto-Config (PAC).

  - Data sent in multipart channels ignores referrer-policy response headers.

  - WebExtensions can use data: protocol to affect other extensions.

  - Content about: pages can load privileged about: pages.

  - Remove addons.mozilla.org CDN from whitelist for mozAddonManager.

  - Disclosure of local file existence through TRACK tag error messages.

  - WebRTC can be used to generate a large amount of UDP traffic for DDOS attacks.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  51 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 51
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-01/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"51.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"51.0");
  security_message(data:report);
  exit(0);
}
