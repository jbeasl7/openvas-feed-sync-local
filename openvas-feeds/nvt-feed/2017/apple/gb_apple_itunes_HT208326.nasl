# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812285");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2017-13856", "CVE-2017-13864", "CVE-2017-13866", "CVE-2017-13870",
                "CVE-2017-13884", "CVE-2017-13885", "CVE-2017-15422", "CVE-2017-7151",
                "CVE-2017-7153", "CVE-2017-7156", "CVE-2017-7157", "CVE-2017-7160",
                "CVE-2017-7165", "CVE-2017-7172");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-27 17:56:03 +0000 (Fri, 27 Apr 2018)");
  script_tag(name:"creation_date", value:"2017-12-28 14:47:56 +0530 (Thu, 28 Dec 2017)");
  script_name("Apple iTunes Security Update (HT208326) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - A privacy issue existed in the use of client certificates.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities will allow
  remote attackers to track users by leveraging mishandling of client certificates and also execute
  arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.7.2.");

  script_tag(name:"solution", value:"Update to version 12.7.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208326");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.7.2.58")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.7.2.58", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
