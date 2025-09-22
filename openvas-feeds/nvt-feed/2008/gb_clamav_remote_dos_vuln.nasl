# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800067");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2008-5050");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.94.1 Off-By-One Heap based Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl");
  script_mandatory_keys("clamav/detected");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an off-by-one error in the function
  get_unicode_name() in libclamav/vba_extract.c.");

  script_tag(name:"impact", value:"A specially crafted VBA project when opened causes heap buffer
  overflow which can be exploited by attackers to execute arbitrary code on the system with clamd
  privileges or cause the application to crash.");

  script_tag(name:"affected", value:"ClamAV prior to version 0.94.1.");

  script_tag(name:"solution", value:"Update to version 0.94.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32663");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32207");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46462");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/3085");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=637952;group_id=86638");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "0.94.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.94.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
