# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804280");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-1850", "CVE-2013-1851");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-05 14:00:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Multiple Code Execution & Local File Disclosure Vulnerabilities (May 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple arbitrary code execution and local file disclosure vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper verification of user-uploaded files by apps/contacts/import.php and
apps/contacts/ajax/uploadimport.php scripts.

  - Insufficient sanitization of user-supplied input to lib/migrate.php script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary PHP
code by uploading a '.htaccess' file and gain access to arbitrary files.");
  script_tag(name:"affected", value:"ownCloud Server before version 4.0.13 and 4.5.x before version 4.5.8");
  script_tag(name:"solution", value:"Update to version 4.0.13 or 4.5.8 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58483");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-010");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-009");
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

if(version_is_less(version:version, test_version:"4.0.13")||
   version_in_range(version:version, test_version:"4.5.0", test_version2:"4.5.7")) {
  security_message(port:port);
  exit(0);
}

exit(99);
