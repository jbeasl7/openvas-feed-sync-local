# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803951");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2013-1892");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-10-07 15:50:02 +0530 (Mon, 07 Oct 2013)");
  script_name("MongoDB nativeHelper Denial of Service Vulnerability");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in nativeHelper function
  in SpiderMonkey which fails to validate requests properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to cause a denial of service condition or execute arbitrary
  code via a crafted memory address in the first argument.");

  script_tag(name:"affected", value:"MongoDB version before 2.0.9 and 2.2.x before 2.2.4 on Windows");

  script_tag(name:"solution", value:"Upgrade to MongoDB 2.0.9 or 2.2.4 or 2.4.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mongodb.org/about/alerts");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-9124");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Databases");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(ver =~ "^2\.") {
  if(version_is_less(version: ver, test_version: "2.0.9")) {
    VULN = TRUE;
    fix = "2.0.9";
  }

  else if(version_in_range(version: ver, test_version:"2.2.0", test_version2:"2.2.3")) {
    VULN = TRUE;
    fix = "2.2.4";
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:ver, fixed_version:fix);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
