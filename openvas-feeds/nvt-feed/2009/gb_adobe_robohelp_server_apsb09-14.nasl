# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801103");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-3068");

  script_name("Adobe RoboHelp Server RCE Vulnerability (APSB09-14/APSA09-05)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_robohelp_server_http_detect.nasl", "gb_adobe_robohelp_nd_robohelp_server_smb_login_detect.nasl");
  script_mandatory_keys("adobe/robohelp/server/detected");

  script_tag(name:"summary", value:"Adobe RoboHelp Server is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unrestricted file upload vulnerability in the RoboHelpServer
  Servlet (robohelp/server) allows remote attackers to execute arbitrary code by uploading a Java
  Archive (.jsp) file during a PUBLISH action, then accessing it via a direct request to the file in
  the robohelp/robo/reserved/web directory under its sessionid subdirectory.");

  script_tag(name:"impact", value:"This vulnerability could result in an unauthenticated user
  uploading and executing arbitrary code.");

  script_tag(name:"affected", value:"Adobe RoboHelp Server version 8.0.");

  script_tag(name:"solution", value:"The vendor has released a patch to fix the issue, please see
  the references for more information.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20191230160449/https://www.adobe.com/support/security/bulletins/apsb09-14.html");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/advisories/apsa09-05.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2009/09/potential_robohelp_server_8_is.html");
  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36245");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=26");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36467");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_equal(version: vers, test_version: "8.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "See advisory", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
