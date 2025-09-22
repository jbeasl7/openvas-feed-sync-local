# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809045");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173",
                "CVE-2016-5174", "CVE-2016-5175", "CVE-2016-7549", "CVE-2016-5176");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-09-15 11:32:52 +0530 (Thu, 15 Sep 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_13-2016-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple use after free errors in Blink.

  - An arbitrary Memory Read error in v8

  - An extension resource access error.

  - The popup is not correctly suppressed.

  - Not ensuring that the recipient of a certain IPC message is a valid
    RenderFrame or RenderWidget.

  - An improper SafeBrowsing protection mechanism.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to corrupt memory, to bypass security,
  to reduce performance, to bypass the SafeBrowsing protection mechanism, to
  cause a denial of service and other unspecified impact.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 53.0.2785.113 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  53.0.2785.113 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/09/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92942");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93234");

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

if(version_is_less(version:chr_ver, test_version:"53.0.2785.113"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"53.0.2785.113");
  security_message(data:report);
  exit(0);
}
