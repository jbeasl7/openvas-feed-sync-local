# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812328");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-7845");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-09 16:27:00 +0000 (Thu, 09 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-12-08 11:04:56 +0530 (Fri, 08 Dec 2017)");
  script_name("Mozilla Firefox Security Advisories (MFSA2017-28, MFSA2017-29) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a buffer overflow
  when drawing and validating elements with ANGLE library using Direct 3D 9.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute code on the affected system or cause a
  denial of service condition.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 57.0.2.");

  script_tag(name:"solution", value:"Update to version 57.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-29/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"57.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"57.0.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
