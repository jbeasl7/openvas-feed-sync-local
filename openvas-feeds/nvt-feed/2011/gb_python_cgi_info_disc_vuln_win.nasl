# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801796");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-1015");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_name("Python CGIHTTPServer Module Information Disclosure Vulnerability - Windows");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2254");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46541");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025489");

  script_tag(name:"insight", value:"The flaw is due to an error when handling 'is_cgi' method in
  'CGIHTTPServer.py' in the 'CGIHTTPServer module', which allows an attcker to
  supply a specially crafted request without the leading '/' character to the CGIHTTPServer.");

  script_tag(name:"summary", value:"Python is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Source code patches are available, please see the references for
  more information.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain access to potentially
  sensitive information contained in arbitrary scripts by requesting cgi script
  without / in the beginning of URL.");

  script_tag(name:"affected", value:"Python version 2.5, 2.6, and 3.0.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version:version, test_version:"2.5") ||
   version_is_equal(version:version, test_version:"2.6") ||
   version_is_equal(version:version, test_version:"3.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
