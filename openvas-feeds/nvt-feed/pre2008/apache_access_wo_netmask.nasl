# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14177");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0993");
  script_name("Apache HTTP Server 'mod_access' Rule Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"GLSA", value:"GLSA 200405-22");
  script_xref(name:"MDKSA", value:"MDKSA-2004:046");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0027");

  script_xref(name:"URL", value:"http://www.apacheweek.com/features/security-13");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9829");
  script_xref(name:"URL", value:"https://marc.info/?l=apache-cvs&m=107869603013722");
  script_xref(name:"URL", value:"http://nagoya.apache.org/bugzilla/show_bug.cgi?id=23850");

  script_tag(name:"solution", value:"Update to Apache version 1.3.31 or newer.");

  script_tag(name:"summary", value:"The target is running an Apache web server that may not properly handle
  access controls.");

  script_tag(name:"insight", value:"In effect, on big-endian 64-bit platforms, Apache
  fails to match allow or deny rules containing an IP address but not a netmask.
  Additional information on the vulnerability can be found at the referenced links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.3.31")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.31", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);