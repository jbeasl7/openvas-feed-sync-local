# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108386");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2016-3498", "CVE-2016-3511", "CVE-2016-3606");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-07-25 11:28:15 +0530 (Mon, 25 Jul 2016)");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities-02 (Jul 2016) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A flaw in the Hotspot component.

  - A flaw in the JavaFX component.

  - A flaw in the Deployment component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users
  to cause denial of service conditions on the target system, a remote or local user
  can obtain elevated privileges on the target system.");

  script_tag(name:"affected", value:"Oracle Java SE 7 update 101 and prior,
  and 8 update 92 and prior on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91990");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91956");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91912");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^(1\.(7|8))")
{
  if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.101") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.92"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}

exit(99);
