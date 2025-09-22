# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815002");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793",
                "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9797",
                "CVE-2019-9789", "CVE-2019-9799", "CVE-2019-9801", "CVE-2019-9802",
                "CVE-2019-9803", "CVE-2019-9788", "CVE-2019-9805", "CVE-2019-9806",
                "CVE-2019-9807", "CVE-2019-9809", "CVE-2019-9808");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:43:00 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-03-20 12:38:38 +0530 (Wed, 20 Mar 2019)");
  script_name("Mozilla Firefox Security Advisories (MFSA2019-06, MFSA2019-08) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An integer overflow error in Skia.

  - An use-after-free error when removing in-use DOM elements.

  - Multiple type confusion errors through on-stack replacement with IonMonkey.

  - An error in IonMonkey just-in-time (JIT) compiler.

  - An improper bounds checks when Spectre mitigations are disabled.

  - Command line arguments not discarded during Firefox invocation as a shell
    handler for URLs.

  - A type confusion error in IonMonkey JIT compiler.

  - An use-after-free error with SMIL animation controller.

  - Cross-origin theft of images with createImageBitmap.

  - An insufficient bounds checking of data during inter-process communication.

  - Windows programs that are not 'URL Handlers' are exposed to web content.

  - A memory read error in Chrome process.

  - Upgrade-Insecure-Requests incorrectly enforced for same-origin navigation.

  - Use of uninitialized memory in Prio library.

  - A vulnerability exists during authorization prompting for FTP transaction.

  - Text sent through FTP connection can be incorporated into alert messages.

  - WebRTC permissions can display incorrect origin with data: and blob: URLs.

  - An error in handling FTP modal alert error messages.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to run arbitrary code, cause denial of service, disclose sensitive information
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  66 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 66
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-07");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"66")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"66", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
