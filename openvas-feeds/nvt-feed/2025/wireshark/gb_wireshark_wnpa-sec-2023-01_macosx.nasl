# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836351");
  script_version("2025-05-23T05:40:17+0000");
  script_cve_id("CVE-2023-0414");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-05-23 05:40:17 +0000 (Fri, 23 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-01 16:22:03 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"creation_date", value:"2025-05-22 14:41:36 +0530 (Thu, 22 May 2025)");
  script_name("Wireshark Security Update (wnpa-sec-2023-01) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service via packet injection or crafted capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.0.0 through 4.0.2 on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 4.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-01.html");
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "4.0.0", test_version2: "4.0.2")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.0.3", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);