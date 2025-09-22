# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803806");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2013-0991", "CVE-2013-0992", "CVE-2013-0993", "CVE-2013-0994",
                "CVE-2013-0995", "CVE-2013-0996", "CVE-2013-0997", "CVE-2013-0998",
                "CVE-2013-0999", "CVE-2013-1000", "CVE-2013-1001", "CVE-2013-1002",
                "CVE-2013-1003", "CVE-2013-1004", "CVE-2013-1005", "CVE-2013-1006",
                "CVE-2013-1007", "CVE-2013-1008", "CVE-2013-1010", "CVE-2013-1011",
                "CVE-2013-1014");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2013-06-06 13:03:34 +0530 (Thu, 06 Jun 2013)");
  script_name("Apple iTunes Multiple Vulnerabilities (Jun 2013) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws due to

  - Improper validation of SSL certificates.

  - Integer overflow error within the 'string.replace()' method.

  - Some vulnerabilities are due to a bundled vulnerable version of WebKit.

  - Array indexing error when handling JSArray objects.

  - Boundary error within the 'string.concat()' method.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary code, conduct Man-in-the-Middle (MitM) attack or cause heap-based buffer overflow.");

  script_tag(name:"affected", value:"Apple iTunes prior to version 11.0.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 11.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59941");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59944");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59953");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59955");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59956");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59957");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59958");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59959");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59960");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59963");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59964");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59967");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59971");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59972");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59974");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59977");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53471");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2013/May/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_is_less(version:version, test_version:"11.0.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"11.0.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
