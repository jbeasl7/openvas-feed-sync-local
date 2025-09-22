# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804659");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2013-0204");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-03 14:00:12 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud PHP Code Execution Vulnerability (Jul 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists as the input passed via the '/settings/personal.php' script is
not properly sanitized before being returned to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary php
code.");
  script_tag(name:"affected", value:"ownCloud Server 4.5.x before 4.5.6");
  script_tag(name:"solution", value:"Update to version 4.5.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57497");
  script_xref(name:"URL", value:"http://owncloud.org/security/advisory/?id=oC-SA-2013-002");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"4.5.0", test_version2:"4.5.5")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"4.5.0 - 4.5.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
