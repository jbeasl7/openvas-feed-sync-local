# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808296");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2016-5141", "CVE-2016-5142", "CVE-2016-5139", "CVE-2016-5140",
                "CVE-2016-5145", "CVE-2016-5143", "CVE-2016-5144", "CVE-2016-5146");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-08-04 15:10:25 +0530 (Thu, 04 Aug 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2016-08) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An address bar spoofing vulnerability.

  - An use-after-free error in Blink.

  - Multiple heap overflow errors in pdfium.

  - A same origin bypass error for images in Blink.

  - Parameter sanitization failure in DevTools.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to conduct spoofing attacks on a
  targeted system, to bypass security, to corrupt memory, to execute arbitrary
  code and to cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  52.0.2743.116 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  52.0.2743.116 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/08/stable-channel-update-for-desktop.html");

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

if(version_is_less(version:chr_ver, test_version:"52.0.2743.116"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"52.0.2743.116");
  security_message(data:report);
  exit(0);
}
