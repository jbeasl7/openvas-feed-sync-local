# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804232");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-3102", "CVE-2012-0841", "CVE-2012-2807", "CVE-2012-2825",
                "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-5134", "CVE-2013-1024",
                "CVE-2013-1037", "CVE-2013-1038", "CVE-2013-1039", "CVE-2013-1040",
                "CVE-2013-1041", "CVE-2013-1042", "CVE-2013-1043", "CVE-2013-1044",
                "CVE-2013-1045", "CVE-2013-1046", "CVE-2013-1047", "CVE-2013-2842",
                "CVE-2013-5125", "CVE-2013-5126", "CVE-2013-5127", "CVE-2013-5128",
                "CVE-2014-1242");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-01-30 16:54:49 +0530 (Thu, 30 Jan 2014)");
  script_name("Apple iTunes Multiple Vulnerabilities (HT6001) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2013-1024: Uninitialized memory access issue in the handling of text tracks

  - CVE-2014-1242: iTunes Tutorials window uses a non-secure HTTP connection to retrieve content.

  - Multiple memory corruption issues in WebKit, libxml and libxslt");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to perform
  man-in-the-middle attacks and obtain sensitive information, cause unexpected application
  termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Apple iTunes before 11.1.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 11.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90653");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65088");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(version_is_less(version:version, test_version:"11.1.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"11.1.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
