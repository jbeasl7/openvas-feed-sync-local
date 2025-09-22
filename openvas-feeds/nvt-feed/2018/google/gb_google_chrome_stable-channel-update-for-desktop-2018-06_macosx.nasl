# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813517");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2018-6148");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-02 13:57:00 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-06-07 11:05:17 +0530 (Thu, 07 Jun 2018)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2018-06) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to incorrect handling of
  CSP header.");

  script_tag(name:"impact", value:"Successful exploitation could allow an
  attacker to perform cross-site scripting, clickjacking and other types of code
  injection attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 67.0.3396.79 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  67.0.3396.79 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");


  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/06/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(version_is_less(version:chr_ver, test_version:"67.0.3396.79"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"67.0.3396.79");
  security_message(data:report);
  exit(0);
}

exit(0);
