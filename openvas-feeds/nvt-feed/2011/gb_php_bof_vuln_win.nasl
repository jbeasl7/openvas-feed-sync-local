# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902436");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-1938");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP 'socket_connect()' Buffer Overflow Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/May/472");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47950");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101665/cve20111938.txt");
  script_xref(name:"URL", value:"http://www.bugsearch.net/en/11873/php-535-socketconnect-buffer-overflow-vulnerability-cve-2011-1938.html?ref=3");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code or to cause denial of service condition.");

  script_tag(name:"affected", value:"PHP Version 5.3.5 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'socket_connect()' function
  within socket module. It uses memcpy to copy path from addr to s_un without
  checking addr length in case when AF_UNIX socket is used.");

  script_tag(name:"solution", value:"Update to version 5.3.7 or later.");

  script_tag(name:"summary", value:"PHP is prone to a stack buffer overflow vulnerability.");

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

if(version_is_less_equal(version:vers, test_version:"5.3.5")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.7");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
