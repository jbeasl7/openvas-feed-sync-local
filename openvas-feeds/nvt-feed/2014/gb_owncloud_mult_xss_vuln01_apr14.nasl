# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804361");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-0201", "CVE-2013-0202", "CVE-2013-0203");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 19:39:00 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2014-04-04 14:54:56 +0530 (Fri, 04 Apr 2014)");
  script_name("ownCloud Multiple XSS Vulnerabilities-01 (Apr 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple XSS vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Unspecified input passed to core/lostpassword/templates/resetpassword.php is
  not properly sanitized before being used.

  - Input passed via the 'mime' parameter to apps/files/ajax/mimeicon.php is not
  properly sanitized before being used.

  - Input passed via the 'token' parameter to apps/gallery/sharing.php is not
  properly sanitized before being used.

  - Input passed via the 'action' parameter to core/ajax/sharing.php is not
  properly sanitized before being used.

  - Unspecified input passed to apps/calendar/ajax/event/new.php is not
  properly sanitized before being used.

  - Input passed via the 'url' parameter to apps/bookmarks/ajax/addBookmark.php
  is not properly sanitized before being used.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser within the trust relationship between their browser
and the server.");
  script_tag(name:"affected", value:"ownCloud Server version 4.5.x before 4.5.6 and 4.0.x before 4.0.11");
  script_tag(name:"solution", value:"Update to version 4.5.6 or 4.0.11 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57497");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/01/22/12");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oc-sa-2013-001");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"4.5.0", test_version2:"4.5.5")||
   version_in_range(version:version, test_version:"4.0.0", test_version2:"4.0.10")) {
  security_message(port:port);
  exit(0);
}

exit(99);
