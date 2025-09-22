# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804735");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2014-1549", "CVE-2014-1548", "CVE-2014-1560", "CVE-2014-1559",
                "CVE-2014-1547", "CVE-2014-1558", "CVE-2014-1552", "CVE-2014-1555",
                "CVE-2014-1557", "CVE-2014-1544", "CVE-2014-1556", "CVE-2014-1550");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-08-07 16:04:43 +0530 (Thu, 07 Aug 2014)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 (Aug 2014) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error when buffering Web Audio for playback.

  - A use-after-free error related to ordering of control messages for Web Audio.

  - A use-after-free error when handling the FireOnStateChange event.

  - An unspecified error when using the Cesium JavaScript library to generate
  WebGL content.

  - The application bundles a vulnerable version of the Network Security
  Services (NSS) library.
and Some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version before 31.0 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 31.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68810");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68813");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68814");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68815");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68824");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-57.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"31.0"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"31.0");
  security_message(port:0, data:report);
  exit(0);
}
