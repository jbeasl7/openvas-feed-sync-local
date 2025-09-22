# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809303");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2016-8878", "CVE-2016-8879", "CVE-2016-8877", "CVE-2016-8876",
                "CVE-2016-8875");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-29 19:27:00 +0000 (Tue, 29 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-11-03 13:36:41 +0530 (Thu, 03 Nov 2016)");
  script_name("Foxit Reader < 8.1 Multiple Vulnerabilities (Nov 2016) - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The heap buffer overflow and heap corruption vulnerabilities.

  - An Use-After-Free vulnerability.

  - An Out-of-Bounds Read or Out-of-Bounds Write vulnerability.

  - A Null Pointer Deference vulnerability.

  - An Integer Overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to leak sensitive information, execute remote code and also to cause a
  denial of service condition(application crash).");

  script_tag(name:"affected", value:"Foxit Reader version prior to 8.1.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version
  8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93608");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:version, test_version:"8.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.1");
  security_message(data:report);
  exit(0);
}

exit(99);
