# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806609");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2015-5928", "CVE-2015-5929", "CVE-2015-5930", "CVE-2015-5931",
                "CVE-2015-6975", "CVE-2015-6992", "CVE-2015-7002", "CVE-2015-7011",
                "CVE-2015-7012", "CVE-2015-7013", "CVE-2015-7014", "CVE-2015-7017");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-11-03 14:51:27 +0530 (Tue, 03 Nov 2015)");
  script_name("Apple iTunes Multiple Vulnerabilities (Nov 2015) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple memory corruption issues in WebKit.

  - Multiple memory corruption issues in the processing of text files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or conduct denial of service condition on the affected system.");

  script_tag(name:"affected", value:"Apple iTunes versions prior to 12.3.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205372");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77270");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Oct/msg00006.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.3.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.3.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
