# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802504");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-08 13:11:11 +0530 (Tue, 08 Nov 2011)");
  script_cve_id("CVE-2011-3379");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP 'is_a()' Function Remote Arbitrary Code Execution Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46107/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49754");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=741020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519770/30/0/threaded");
  script_xref(name:"URL", value:"http://www.byte.nl/blog/2011/09/23/security-bug-in-is_a-function-in-php-5-3-7-5-3-8/");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary PHP code by including arbitrary files from remote resources.");

  script_tag(name:"affected", value:"PHP Version 5.3.7 and 5.3.8 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in 'is_a()' function. It receives
  strings as first argument, which can lead to the '__autoload()' function being
  called unexpectedly and do not properly verify input in their '__autoload()'
  function, which leads to an unexpected attack vectors.");

  script_tag(name:"solution", value:"Update to version 5.3.9 or later.");

  script_tag(name:"summary", value:"PHP is prone to a remote arbitrary code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:vers, test_version:"5.3.7") ||
  version_is_equal(version:vers, test_version:"5.3.8")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.9");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
