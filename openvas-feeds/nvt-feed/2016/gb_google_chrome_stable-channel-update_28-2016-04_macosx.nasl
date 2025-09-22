# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807573");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1662", "CVE-2016-1663",
                "CVE-2016-1664", "CVE-2016-1665", "CVE-2016-1666", "CVE-2016-5168");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-05-02 14:07:18 +0530 (Mon, 02 May 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update_28-2016-04) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out-of-bounds write error in Blink.

  - Memory corruption in cross-process frames.

  - An use-after-free error in extensions.

  - An Use-after-free error in Blink's V8 bindings.

  - Address bar spoofing vulnerability.

  - An information leak in V8.

  - The Various fixes from internal audits, fuzzing, and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow an unauthenticated, remote attacker to gain access
  to sensitive information, to execute arbitrary code, to cause a denial of
  service (DoS) condition and to conduct spoofing attacks on a targeted system.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 50.0.2661.94 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  50.0.2661.94 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/04/stable-channel-update_28.html");

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

if(version_is_less(version:chr_ver, test_version:"50.0.2661.94"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"50.0.2661.94");
  security_message(data:report);
  exit(0);
}
