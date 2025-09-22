# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834790");
  script_version("2024-12-06T05:05:38+0000");
  script_cve_id("CVE-2023-6174");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-12-06 05:05:38 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 17:27:06 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-12-03 17:45:48 +0530 (Tue, 03 Dec 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2023-28) - Linux");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service via packet injection or crafted capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.0.0 through 4.0.10 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 4.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2023-28.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version: vers, test_version: "4.0.0", test_version2: "4.0.10")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.0.11", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
