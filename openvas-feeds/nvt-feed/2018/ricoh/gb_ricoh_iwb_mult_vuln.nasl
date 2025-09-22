# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141737");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-29 13:44:18 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-16184", "CVE-2018-16185", "CVE-2018-16186", "CVE-2018-16187", "CVE-2018-16188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Interactive Whiteboard Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ricoh_iwb_detect.nasl");
  script_mandatory_keys("ricoh_iwb/detected");

  script_tag(name:"summary", value:"RICOH Interactive Whiteboard is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"RICOH Interactive Whiteboard is prone to multiple vulnerabilities:

  - A remote attacker may execute an arbitrary command with the administrative privilege (CVE-2018-16184)

  - A remote attacker may execute an altered program (CVE-2018-16185)

  - An attacker may log in to the administrator settings screen and change the configuration (CVE-2018-16186)

  - A man-in-the-middle attack allows an attacker to eavesdrop on an encrypted communication (CVE-2018-16187)

  - A remote attacker may obtain or alter the information in the database (CVE-2018-16188)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN55263945/");
  script_xref(name:"URL", value:"https://www.ricoh.com/info/2018/1127_1.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:ricoh:iwb_d2200_firmware",
                     "cpe:/o:ricoh:iwb_d5500_firmware",
                     "cpe:/o:ricoh:iwb_d5510_firmware",
                     "cpe:/o:ricoh:iwb_d5520_firmware",
                     "cpe:/o:ricoh:iwb_d6500_firmware",
                     "cpe:/o:ricoh:iwb_d6510_firmware",
                     "cpe:/o:ricoh:iwb_d7500_firmware",
                     "cpe:/o:ricoh:iwb_d8400_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe  = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port))
  exit(0);

if (cpe == "cpe:/o:ricoh:iwb_d2200_firmware") {
  if (version_is_less(version: version, test_version: "2.6.00000.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.6.00000.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:ricoh:iwb_d5500_firmware") {
  if (version_is_less(version: version, test_version: "2.3.00018.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.3.00018.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:ricoh:iwb_d5510_firmware") {
  if (version_is_less(version: version, test_version: "2.3.00017.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.3.00017.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

else if (version_is_less(version: version, test_version: "2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

else if (version =~ "^3\." && version_is_less(version: version, test_version: "3.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
