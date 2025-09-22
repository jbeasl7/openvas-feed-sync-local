# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807890");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2016-4728", "CVE-2016-4758", "CVE-2016-4759", "CVE-2016-4760",
                "CVE-2016-4762", "CVE-2016-4763", "CVE-2016-4764", "CVE-2016-4765",
                "CVE-2016-4766", "CVE-2016-4767", "CVE-2016-4768", "CVE-2016-4769");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-11 17:56:00 +0000 (Mon, 11 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-09-28 15:03:42 +0530 (Wed, 28 Sep 2016)");
  script_name("Apple iTunes Multiple Vulnerabilities (Sep 2016) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A parsing issue in the handling of error prototypes.

  - A permissions issue in the handling of the location variable.

  - Multiple memory corruption issues.

  - Cross-protocol exploitation of non-HTTP services using DNS rebinding.

  - A certificate validation issue in the handling of WKWebView.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code, intercept and alter network traffic, access non-HTTP services and gain access to
  potentially sensitive information.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.5.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207158");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93062");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:version, test_version:"12.5.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.5.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
