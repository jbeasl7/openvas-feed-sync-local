# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:visual_mining:netcharts_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805643");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-4031", "CVE-2015-4032");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-03 12:12:21 +0530 (Wed, 03 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("NetCharts Server Multiple Vulnerabilities");

  script_tag(name:"summary", value:"NetCharts Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is installed with vulnerable version or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The projectContents.jsp script in developer tools does not properly verify
    or sanitize user-uploaded files.

  - The saveFile.jsp script in developer installation not properly sanitizing
    user input, specifically path traversal style attacks");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to write to arbitrary files via unspecified vectors, rename files
  and execute arbitrary PHP code.");

  script_tag(name:"affected", value:"Visual Mining NetChart Server");

  script_tag(name:"solution", value:"As a workaround restrict interaction with
  the service to trusted machines. Only the clients and servers that have a
  legitimate procedural relationship with the service should be permitted to
  communicate with it.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-238/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74788");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-237/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netcharts_server_detect.nasl");
  script_mandatory_keys("netchart/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_equal(version:version, test_version:"7.0.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Workaround");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
