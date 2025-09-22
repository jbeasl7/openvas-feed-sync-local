# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814415");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2018-12392", "CVE-2018-12395", "CVE-2018-12396", "CVE-2018-12397",
                "CVE-2018-12398", "CVE-2018-12399", "CVE-2018-12401", "CVE-2018-12402",
                "CVE-2018-12403", "CVE-2018-12388", "CVE-2018-12390");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-24 15:55:07 +0530 (Wed, 24 Oct 2018)");
  script_name("Mozilla Firefox Security Advisories (MFSA2018-25, MFSA2018-27) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Poor event handling in nested loops while opening a document through script.

  - A WebExtension can bypass domain restrictions through domain fronting.

  - A WebExtension can run content scripts in disallowed contexts following
    navigation or other events.

  - A WebExtension can request access to local files without the warning prompt.

  - Content Security Policy (CSP) error in resource URIs.

  - Spoofing of protocol registration notification bar.

  - Cookie policy violation on cross-origin requests.

  - Mixed content warning is not displayed when HTTPS page loads a favicon over
    HTTP.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, denial of servic, cause denial of service and conduct
  spoofing attack.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 63 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 63
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-26");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"63")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"63", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
