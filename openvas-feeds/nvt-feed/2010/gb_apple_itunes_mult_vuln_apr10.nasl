# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800495");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2010-0531", "CVE-2010-0532");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_name("Apple iTunes Multiple Vulnerabilities (APPLE-SA-2010-03-30-2)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An infinite loop issue in the handling of 'MP4' files. A maliciously crafted podcast may be able
  to cause an infinite loop in iTunes, and prevent its operation even after it is relaunched.

  - A privilege escalation issue in Windows installation package. During the installation process, a
  race condition may allow a local user to modify a file that is then executed with system
  privileges.");

  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to cause
  denial of service and obtain system privileges during installation.");

  script_tag(name:"affected", value:"Apple iTunes prior to version 9.1 (9.1.0.79).");

  script_tag(name:"solution", value:"Update to version 9.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39135");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392444.php");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010//Mar/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
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

if(version_is_less(version:version, test_version:"9.1.0.79")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.1.0.79", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
