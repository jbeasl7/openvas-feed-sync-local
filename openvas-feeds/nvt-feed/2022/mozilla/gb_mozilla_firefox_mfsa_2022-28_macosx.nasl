# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821197");
  script_version("2025-06-04T05:40:50+0000");
  script_cve_id("CVE-2022-36319", "CVE-2022-2505", "CVE-2022-36318", "CVE-2022-36315",
                "CVE-2022-36316", "CVE-2022-36320");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 21:29:00 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-07-28 14:20:54 +0530 (Thu, 28 Jul 2022)");
  script_name("Mozilla Firefox Security Advisory (MFSA2022-28) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Mouse Position spoofing with CSS transforms.

  - Directory indexes for bundled resources reflected URL parameters.

  - Opening local <code>.lnk</code> files could cause unexpected network loads.

  - Preload Cache Bypasses Subresource Integrity.

  - Performance API leaked whether a cross-site resource is redirecting.

  - Memory safety.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  103 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 103
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-28");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"103")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"103", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
