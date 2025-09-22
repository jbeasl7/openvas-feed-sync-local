# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834462");
  script_version("2024-09-05T15:07:28+0000");
  script_cve_id("CVE-2024-8250");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 15:07:28 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-30 16:32:16 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-02 12:07:28 +0530 (Mon, 02 Sep 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2024-11) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to an use after free
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an issue in NTLMSSP
  dissector.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause denial of service.");

  script_tag(name:"affected", value:"Wireshark version 4.0.0 through 4.0.16
  and 4.2.0 through 4.2.6 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 4.0.17 or 4.2.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-11.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.16")) {
  fix = "4.0.17";
}

if(version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.6")) {
  fix = "4.2.7";
}

if(fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
