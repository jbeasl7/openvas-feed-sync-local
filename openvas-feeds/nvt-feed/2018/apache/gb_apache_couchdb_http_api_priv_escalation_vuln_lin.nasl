# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813907");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-08-09 15:19:22 +0530 (Thu, 09 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-13 19:29:00 +0000 (Mon, 13 May 2019)");

  script_cve_id("CVE-2018-8007");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Apache CouchDB 1.x < 1.7.2, 2.x < 2.1.2 Privilege Escalation Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation of
  administrator-supplied configuration settings via the HTTP API.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to escalate their
  privileges to that of the operating system's and execute arbitrary code.");

  script_tag(name:"affected", value:"Apache CouchDB versions 1.x prior to 1.7.2 and 2.x prior to
  2.1.2.");

  script_tag(name:"solution", value:"Update to version 1.7.2, 2.1.2 or later.
  Please see the references for more information.");

  script_xref(name:"URL", value:"https://blog.couchdb.org/2018/07/10/cve-2018-8007");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104741");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.7.2"))
  fix = "1.7.2";

else if(version_in_range(version:version, test_version:"2.0", test_version2:"2.1.1"))
  fix = "2.1.2";

if(fix)
{
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
