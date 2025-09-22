# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opensc-project:opensc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834625");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-45615", "CVE-2024-45616", "CVE-2024-45617", "CVE-2024-45618",
                "CVE-2024-45619", "CVE-2024-45620");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-23 23:26:14 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-23 17:31:27 +0530 (Mon, 23 Sep 2024)");
  script_name("OpenSC Multiple Vulnerabilities (Sep 2024) - Linux");

  script_tag(name:"summary", value:"OpenSC is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-45616: An insufficient control of the response APDU buffer and its length when communicating with the card.

  - CVE-2024-45617: Insufficient or missing checking of return values of functions leads to unexpected work with variables that have not been initialized.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code, disclose information and cause denial of service
  attacks.");

  script_tag(name:"affected", value:"OpenSC prior to version 0.26.0 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 0.26.0 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2024-45616");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2309290");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opensc_detect.nasl");
  script_mandatory_keys("opensc/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version: vers, test_version: "0.26.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.26.0", install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);