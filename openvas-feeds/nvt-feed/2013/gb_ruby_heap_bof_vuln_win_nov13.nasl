# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ruby-lang:ruby";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903502");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2013-4164");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-11-27 20:39:27 +0530 (Wed, 27 Nov 2013)");
  script_name("Ruby Interpreter Heap Overflow Vulnerability (Nov 2013) - Windows");

  script_tag(name:"summary", value:"Ruby Interpreter is prone to a heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 1.9.3 patchlevel 484, 2.0.0 patchlevel 353 or
  later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization while processing user supplied
  input data during conversion of strings to floating point values.");

  script_tag(name:"affected", value:"Ruby Interpreter version 1.8, 1.9 before 1.9.3 Patchlevel 484, 2.0 before
  2.0.0 Patchlevel 353.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause denial of service
  or potentially the execution of arbitrary code.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63873");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89191");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ruby_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ruby/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version:version, test_version:"1.8") ||
   version_in_range(version:version, test_version:"1.9", test_version2:"1.9.3.p483") ||
   version_in_range(version:version, test_version:"2.0", test_version2:"2.0.0.p352")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.9.3-p483 / 2.0.0-p352", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
