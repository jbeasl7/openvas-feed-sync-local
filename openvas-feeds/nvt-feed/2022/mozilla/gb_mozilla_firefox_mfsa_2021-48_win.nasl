# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826505");
  script_version("2025-06-04T05:40:50+0000");
  script_cve_id("CVE-2021-38505");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 17:02:00 +0000 (Fri, 10 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-09-09 18:00:25 +0530 (Fri, 09 Sep 2022)");
  script_name("Mozilla Firefox Security Advisory (MFSA2021-48) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Cloud Clipboard enabled
  on Windows 10, which will record data copied to the clipboard to the cloud,
  and make it available on other computers in certain scenarios.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to leak sensitive data.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  94 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 94
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
   # nb: This bug only affects Firefox for Windows 10+ with Cloud Clipboard enabled.
  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-48/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"94")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"94", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
