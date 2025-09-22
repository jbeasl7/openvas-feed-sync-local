# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804655");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2013-0302");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-07-03 11:17:12 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Amazon SDK Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"ownCloud is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to an error in the Amazon SDK testing suite bundled within
the application.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain knowledge of
potentially sensitive information.");
  script_tag(name:"affected", value:"ownCloud Server 4.0.x before 4.0.12");
  script_tag(name:"solution", value:"Update to version 4.0.12 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52303");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58108");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-005");
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

if(version_in_range(version:version, test_version:"4.0.0", test_version2:"4.0.11")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"4.0.0 - 4.0.11");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
