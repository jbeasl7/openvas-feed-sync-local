# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804279");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-1822");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-05 13:20:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Multiple Cross Site Scripting Vulnerabilities -01 (May 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple cross-site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to insufficient validation of user-supplied input
passed via the 'quota' POST parameter to setquota.php within
/core/settings/ajax, 'group' parameter passed to the settings.php script and
'shareWith' parameter passed to the core/js/share.js script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
script code in a user's browser within the trust relationship between their
browser and the server.");
  script_tag(name:"affected", value:"ownCloud Server 4.5.x before version 4.5.8");
  script_tag(name:"solution", value:"Update to version 4.5.8 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58482");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-008");
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

if(version_in_range(version:version, test_version:"4.5.0", test_version2:"4.5.7")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"4.5.0 - 4.5.7");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
