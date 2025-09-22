# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810228");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2016-9651", "CVE-2016-5208", "CVE-2016-5207", "CVE-2016-5206",
                "CVE-2016-5205", "CVE-2016-5204", "CVE-2016-5209", "CVE-2016-5203",
                "CVE-2016-5210", "CVE-2016-5212", "CVE-2016-5211", "CVE-2016-5213",
                "CVE-2016-5214", "CVE-2016-5216", "CVE-2016-5215", "CVE-2016-5217",
                "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5221", "CVE-2016-5220",
                "CVE-2016-5222", "CVE-2016-9650", "CVE-2016-5223", "CVE-2016-5226",
                "CVE-2016-5225", "CVE-2016-5224", "CVE-2016-9652");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-07 21:15:00 +0000 (Fri, 07 Feb 2020)");
  script_tag(name:"creation_date", value:"2016-12-05 12:51:42 +0530 (Mon, 05 Dec 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2016-12) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A private property access error in V8.

  - The multiple universal XSS errors in Blink.

  - A same-origin bypass error in PDFium.

  - An out of bounds write error in Blink.

  - The multiple  use after free errors.

  - An out of bounds write error in PDFium.

  - A local file disclosure error in DevTools.

  - A file download protection bypass error.

  - The usage of unvalidated data in PDFium.

  - The multiple address spoofing errors in Omnibox.

  - An integer overflow error in ANGLE.

  - A local file access error in PDFium.

  - A CSP Referrer disclosure error.

  - An integer overflow error in PDFium.

  - A CSP bypass error in Blink.

  - A same-origin bypass error in SVG.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to bypass security, obtain
  sensitive information and to execute arbitrary code or cause denial of service
  condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 55.0.2883.75 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 55.0.2883.75 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.in/2016/12/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"55.0.2883.75"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"55.0.2883.75");
  security_message(data:report);
  exit(0);
}
