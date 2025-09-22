# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811057");
  script_version("2024-02-29T14:37:57+0000");
  script_cve_id("CVE-2016-3104");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-29 14:37:57 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-22 14:15:00 +0000 (Sat, 22 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-05-29 14:20:50 +0530 (Mon, 29 May 2017)");
  script_name("MongoDB DoS Vulnerability (May 2017) - Windows");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'in-memory'
  database representation when authenticating against a non-existent database.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service. In very extreme cases the increase in
  memory consumption may cause mongod to run out of memory and either terminate or
  be terminated by the operating system's OOM killer.");

  script_tag(name:"affected", value:"MongoDB version 2.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.6, 3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-24378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94929");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

##Replace '-' by '.' in version
if("-rc" >< version)
  version = ereg_replace(pattern:"-", replace:".", string:version);

if(version == "2.4.0") {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.6.0 or 3.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
