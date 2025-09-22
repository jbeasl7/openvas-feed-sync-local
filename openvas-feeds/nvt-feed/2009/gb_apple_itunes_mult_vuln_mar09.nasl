# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800543");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2009-0016", "CVE-2009-0143");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_name("Apple iTunes Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following issues exist:

  - the origin of an authentication request is not properly informed to the user

  - an error is generated while processing a Digital Audio Access Protocol (DAAP) message containing
  specially crafted Content-Length parameter in the header of a DAAP message");

  script_tag(name:"impact", value:"This issue may be exploited to gain the user's iTune
  credentials when subscribing to a malicious podcast and to cause denial of service.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 8.1.0.51 on Windows.");

  script_tag(name:"solution", value:"Update to version 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3487");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34094");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34254");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
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

if(version_is_less(version:version, test_version:"8.1.0.51")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.1.0.51", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
