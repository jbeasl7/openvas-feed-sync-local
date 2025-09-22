# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809351");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-6494");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-28 13:04:00 +0000 (Tue, 28 Nov 2017)");
  script_tag(name:"creation_date", value:"2016-10-13 15:38:52 +0530 (Thu, 13 Oct 2016)");
  script_name("MongoDB Client 'dbshell' Information Disclosure Vulnerability (SERVER-25335) - Windows");

  script_tag(name:"summary", value:"MongoDB is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to mongodb-clients stores its history in
  '~/.dbshell', this file is created with permissions 0644. Home folders are world readable as
  well.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to obtain
  sensitive information by reading .dbshell history files.");

  script_tag(name:"affected", value:"MongoDB version 2.4.10 and probably earlier.");

  script_tag(name:"solution", value:"Update to version 3.0, 3.2, 3.3.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-25335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92204");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832908");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

#nb: Replace '-' by '.' in version
if("-rc" >< vers)
  vers = ereg_replace(pattern:"-", replace:".", string:vers);

if(version_is_less(version:vers, test_version:"3.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0 / 3.2 / 3.3.14");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);