# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834458");
  script_version("2024-09-05T15:07:28+0000");
  script_cve_id("CVE-2024-7969", "CVE-2024-8193", "CVE-2024-8194", "CVE-2024-8198");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 15:07:28 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-30 15:52:02 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-29 10:40:41 +0530 (Thu, 29 Aug 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_28-2024-08) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7969: Type Confusion in V8

  - CVE-2024-8193: Heap buffer overflow in Skia

  - CVE-2024-8194: Type Confusion in V8

  - CVE-2024-8198: Heap buffer overflow in Skia");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to potentially exploit heap corruption via a crafted HTML page.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  128.0.6613.113 on Linux");

  script_tag(name: "solution", value:"Update to version 128.0.6613.113 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_28.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"128.0.6613.113")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.0.6613.113", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
