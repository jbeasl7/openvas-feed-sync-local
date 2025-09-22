# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800079");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2008-5314");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.94.2 Remote DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl");
  script_mandatory_keys("clamav/detected");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The application fails to validate user input passed to
  cli_check_jpeg_exploit, jpeg_check_photoshop, and jpeg_check_photoshop_8bim functions in special.c
  file.");

  script_tag(name:"impact", value:"Successful exploitation will cause remote attackers to crash
  the daemon via a specially crafted JPEG file.");

  script_tag(name:"affected", value:"ClamAV prior to version 0.94.2.");

  script_tag(name:"solution", value:"Update to version 0.94.2 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/12/01/8");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32555");
  script_xref(name:"URL", value:"http://lurker.clamav.net/message/20081126.150241.55b1e092.en.html");

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

if (version_is_less(version: version, test_version: "0.94.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.94.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
