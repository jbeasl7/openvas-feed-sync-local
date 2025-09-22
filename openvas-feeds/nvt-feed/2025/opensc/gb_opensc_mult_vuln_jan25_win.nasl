# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opensc-project:opensc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834922");
  script_version("2025-01-31T05:37:27+0000");
  script_cve_id("CVE-2023-5992", "CVE-2024-1454");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:00:01 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2025-01-28 21:05:41 +0530 (Tue, 28 Jan 2025)");
  script_name("OpenSC Multiple Vulnerabilities (Jan 2025) - Windows");

  script_tag(name:"summary", value:"OpenSC is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-5992: Side-channel leaks while stripping encryption PKCS#1.5 padding in OpenSC

  - CVE-2024-1454: Potential use-after-free in AuthentIC driver during card enrollment in pkcs15init");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code and disclose information.");

  script_tag(name:"affected", value:"OpenSC prior to version 0.25.0 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 0.25.0 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/releases/tag/0.25.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opensc_detect_win.nasl");
  script_mandatory_keys("opensc/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version: vers, test_version: "0.25.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.25.0", install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);