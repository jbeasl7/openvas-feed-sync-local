# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:idera:uptime_infrastructure_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808235");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-8268");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-10 21:25:00 +0000 (Fri, 10 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-06-27 17:28:12 +0530 (Mon, 27 Jun 2016)");
  script_name("Idera Up.time Agent Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_uptime_infrastructure_monitor_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Idera/Uptime/Infrastructure/Monitor/Installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/204232");

  script_tag(name:"summary", value:"Idera Up.time Agent is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unauthenticated access
  to remote file system that the uptime.agent has read access to.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files from a system running the Up.time agent for
  Linux.");

  script_tag(name:"affected", value:"Up.time agent versions 7.5 and 7.6
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Up.time agent 7.7 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:vers, test_version:"7.5")||
   version_is_equal(version:vers, test_version:"7.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.7");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
