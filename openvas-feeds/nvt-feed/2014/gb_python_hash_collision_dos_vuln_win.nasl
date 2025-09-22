# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804632");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2013-7040");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-09 14:43:46 +0530 (Mon, 09 Jun 2014)");
  script_name("Python 'Hash Collision' Denial of Service Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64194");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/12/09/3");

  script_tag(name:"summary", value:"Python is prone to a denial of service  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error within a hash generation function when hashing form
  posts and updating a hash table.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause a hash collision
  resulting in a denial of service.");

  script_tag(name:"affected", value:"Python version 2.7 before 3.4.");

  script_tag(name:"solution", value:"Update to version 3.4 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

# nb: No need for a version_regex as we only need versions like e.g. 2.7 or 3.3
if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_greater_equal(version:version, test_version:"2.7") && version_is_less(version:version, test_version:"3.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.4", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
