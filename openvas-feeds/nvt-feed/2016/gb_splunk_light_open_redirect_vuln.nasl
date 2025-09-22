# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:light";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809014");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-19 18:49:00 +0000 (Fri, 19 May 2017)");
  script_tag(name:"creation_date", value:"2016-08-26 17:00:30 +0530 (Fri, 26 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Splunk Light Open Redirection Vulnerability");

  script_cve_id("CVE-2016-4859");

  script_tag(name:"summary", value:"Splunk Light is prone to an open redirection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified input
  validation error.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  could permit an attacker to redirect a user to an attacker controlled website.");

  script_tag(name:"affected", value:"Splunk Light version before 6.4.3");

  script_tag(name:"solution", value:"Upgrade to Splunk Light version 6.4.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAPQ6");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_light_detect.nasl");
  script_mandatory_keys("SplunkLight/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"6.4.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.4.3");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
