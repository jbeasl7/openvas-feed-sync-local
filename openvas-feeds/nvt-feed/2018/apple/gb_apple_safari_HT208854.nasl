# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813509");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-4247", "CVE-2018-4205", "CVE-2018-4232", "CVE-2018-4246",
                "CVE-2018-4192", "CVE-2018-4188", "CVE-2018-4214", "CVE-2018-4201",
                "CVE-2018-4218", "CVE-2018-4233", "CVE-2018-4199", "CVE-2018-4190",
                "CVE-2018-4222");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:56:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-06-04 13:35:10 +0530 (Mon, 04 Jun 2018)");
  script_name("Apple Safari Security Updates (HT208854)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A permissions issue in the handling of web browser cookies.

  - A type confusion issue in memory handling.

  - A race condition issue in locking.

  - A memory corruption issue in input validation.

  - A buffer overflow issue in memory handling.

  - Credentials were unexpectedly sent when fetching CSS mask images.

  - An out-of-bounds read issue in input validation.");

  script_tag(name:"impact", value:"Successful exploitation of will allow remote
  attackers to cause a denial of service, conduct spoofing attack, overwrite
  cookies, execute arbitrary code, crash Safari and leak sensitive data.");

  script_tag(name:"affected", value:"Apple Safari versions before 11.1.1.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 11.1.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208854");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.1.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
