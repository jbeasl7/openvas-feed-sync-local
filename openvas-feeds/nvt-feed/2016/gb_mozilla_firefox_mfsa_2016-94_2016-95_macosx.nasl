# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809837");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-9894", "CVE-2016-9899", "CVE-2016-9895", "CVE-2016-9896",
                "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9900", "CVE-2016-9904",
                "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9903", "CVE-2016-9080",
                "CVE-2016-9893");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 17:55:00 +0000 (Fri, 03 Aug 2018)");
  script_tag(name:"creation_date", value:"2016-12-15 13:39:52 +0530 (Thu, 15 Dec 2016)");
  script_name("Mozilla Firefox Security Advisories (MFSA2016-94, MFSA2016-95) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error in SkiaGL.

  - An use-after-free error while manipulating DOM events and audio elements.

  - A CSP bypass error using marquee tag.

  - An Use-after-free error with WebVR.

  - A memory corruption error in libGLES.

  - An use-after-free error in Editor while manipulating DOM subtrees.

  - The restricted external resources can be loaded by SVG images through data URLs.

  - A cross-origin information leak error in shared atoms.

  - The data from Pocket server improperly sanitized before execution.

  - The pocket extension does not validate the origin of events.

  - An XSS injection vulnerability in add-ons SDK.

  - Some memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service, gain sensitive information and also
  could run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 50.1.");

  script_tag(name:"solution", value:"Update to version 50.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-94");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"50.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"50.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
