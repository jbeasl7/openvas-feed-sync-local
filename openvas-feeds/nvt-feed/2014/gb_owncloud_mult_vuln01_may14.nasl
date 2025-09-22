# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804288");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-2041", "CVE-2013-2086", "CVE-2013-2044", "CVE-2013-2047",
                "CVE-2013-2048", "CVE-2013-2085", "CVE-2013-2089");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-06 19:11:33 +0530 (Tue, 06 May 2014)");
  script_name("ownCloud Multiple Vulnerabilities - 01 (May 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Insufficient validation of user-supplied input passed via 'tag' GET parameter
to templates/js_tpl.php script, the 'dir' GET parameter to
apps/files/ajax/newfile.php script, the 'redirect_url' parameter to the
index.php script.

  - An error in configuration loader which includes private data such as CSRF
tokens in a JavaScript file.

  - An error in the index.php script due to the autocomplete setting being
enabled for the 'password' parameter.

  - An insufficient permission check for sensitive transactions.

  - Insufficient sanitization of user-supplied input via the 'dir' GET parameter
to apps/files_trashbin/index.php script.

  - Insufficient verification of user-supplied files for uploading.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary PHP
code, gain access to arbitrary local files, execute API commands as
administrator, conduct cross-site request forgery attacks, gain access to a
user's account or password, redirect users to arbitrary web sites and conduct
phishing attacks, obtain sensitive information and execute arbitrary
script code in a user's browser within the trust relationship between their
browser and the server.");
  script_tag(name:"affected", value:"ownCloud Server 5.0.x before version 5.0.6");
  script_tag(name:"solution", value:"Update to version 5.0.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59962");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59968");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66540");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66542");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-020");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-025");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-023");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-022");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-027");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-021");
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

if(version_in_range(version:version, test_version:"5.0.0", test_version2:"5.0.6")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"5.0.0 - 5.0.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
