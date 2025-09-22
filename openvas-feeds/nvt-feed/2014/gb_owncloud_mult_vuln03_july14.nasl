# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804661");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-3832", "CVE-2014-3834", "CVE-2014-3836", "CVE-2014-3837");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-03 15:47:48 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities-03 (Jul 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Input passed to 'print_unescaped' function in the Documents component is
  not validated before returning it to users.

  - Server fails to verify permissions for users that attempt to rename files
  of other users.

  - HTTP requests do not require multiple steps, explicit confirmation, or a
  unique token when performing certain sensitive actions.

  - Program uses the auto-incrementing file_id instead of randomly generated
  token.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to rename arbitrary files,
gain access to arbitrary contacts of other users, perform a Cross-Site Request
Forgery attack, enumerate shared files of other users and execute arbitrary
script code in a user's browser session within the trust relationship between
their browser and the server.");
  script_tag(name:"affected", value:"ownCloud Server 6.0.x before 6.0.3");
  script_tag(name:"solution", value:"Update to version 6.0.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93682");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67451");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68196");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93689");
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

if(version_in_range(version:version, test_version:"6.0.0", test_version2:"6.0.2")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"6.0.0 - 6.0.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
