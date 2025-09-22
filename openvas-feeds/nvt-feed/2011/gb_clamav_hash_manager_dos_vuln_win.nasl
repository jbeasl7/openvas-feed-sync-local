# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902726");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-2721");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.97.2 Hash Manager Off-By-One DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the way the hash manager of ClamAV scans
  messages with certain hashes.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to provide a
  message with specially-crafted hash signature in it, leading to denial of service (clamscan
  executable crash).");

  script_tag(name:"affected", value:"ClamAV versions prior to 0.97.2 (3.0.3.6870).");

  script_tag(name:"solution", value:"Update to version 0.97.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48891");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68785");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/07/26/3");

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

if (version_is_less(version: version, test_version: "0.97.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.97.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
