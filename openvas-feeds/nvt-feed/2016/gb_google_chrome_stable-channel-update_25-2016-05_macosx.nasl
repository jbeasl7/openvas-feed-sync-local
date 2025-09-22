# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807333");
  script_version("2023-11-08T05:05:52+0000");
  script_cve_id("CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675",
                "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679",
                "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683",
                "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687",
                "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691",
                "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695",
                "CVE-2016-10403");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-08 05:05:52 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-05-30 13:22:34 +0530 (Mon, 30 May 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update_25-2016-05) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Cross-origin bypass in extension bindings.

  - Cross-origin bypass in Blink.

  - Cross-origin bypass in extensions.

  - Type confusion in V8.

  - Heap overflow in V8.

  - Heap use-after-free in V8 bindings.

  - Heap use-after-free in Skia.

  - Heap overflow in PDFium.

  - CSP bypass for ServiceWorker.

  - Out-of-bounds access in libxslt.

  - Integer overflow in libxslt.

  - Out-of-bounds read in PDFium.

  - Information leak in extensions.

  - Out-of-bounds read in V8.

  - Heap buffer overflow in media.

  - Heap use-after-free in Autofill.

  - Heap buffer-overflow in Skia.

  - Limited cross-origin bypass in ServiceWorker.

  - HTTP Download of Software Removal Tool.

  - HPKP pins removed on cache clearance.

  - Insufficient data validation on image data in PDFium.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to bypass security restrictions,
  to obtain sensitive information and to cause a denial of service
  (buffer overflow) or possibly have unspecified other impacts.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 51.0.2704.63 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  51.0.2704.63 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/05/stable-channel-update_25.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"51.0.2704.63"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"51.0.2704.63");
  security_message(data:report);
  exit(0);
}
