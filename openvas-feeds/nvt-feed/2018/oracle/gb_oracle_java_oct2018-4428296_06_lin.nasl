# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814408");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2018-3214");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:27:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-10-17 13:00:33 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Java SE Denial of Service Vulnerability (cpuoct2018) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'Sound'
  component.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause partial denial of service conditions.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0 to 1.6.0.201,
  1.7.0 to 1.7.0.191, 1.8.0 to 1.8.0.182 on Linux.");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun_or_Oracle/Java/JRE/Linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk", "cpe:/a:sun:jre", "cpe:/a:sun:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]") {
  if((version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.191")) ||
     (version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.182")) ||
     (version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.201"))) {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
