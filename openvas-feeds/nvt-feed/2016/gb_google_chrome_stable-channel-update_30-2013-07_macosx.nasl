# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809070");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2013-2881", "CVE-2013-2882", "CVE-2013-2883", "CVE-2013-2884",
                "CVE-2013-2885", "CVE-2013-2886");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-10-19 11:28:07 +0530 (Wed, 19 Oct 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update_30-2013-07) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An origin bypass error in frame handling.

  - A type confusion error in Google V8.

  - An use-after-free error in MutationObserver.

  - An use-after-free in DOM implementation.

  - An use-after-free in input handling.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to cause a denial of service
  or possibly have unspecified other impact and to bypass security.");

  script_tag(name:"affected", value:"Google Chrome version prior to 28.0.1500.95 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  28.0.1500.95 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.in/2013/07/stable-channel-update_30.html");

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

if(version_is_less(version:chr_ver, test_version:"28.0.1500.95"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"28.0.1500.95");
  security_message(data:report);
  exit(0);
}
