# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807852");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2016-4309");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 18:32:00 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-07-04 14:57:33 +0530 (Mon, 04 Jul 2016)");
  script_name("Symphony CMS Session Fixation Vulnerability");

  script_tag(name:"summary", value:"Symphony CMS is prone to a session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists if the application is deployed using an insecure setup
  with a php.ini 'session.use_only_cookies' not enabled and due to an error in application which does not
  use or call 'session_regenerate_id' function upon successful user authentication.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to preset any users PHPSESSID session identifier and access the
  affected application with the same level of access to that of the victim.");

  script_tag(name:"affected", value:"Symphony CMS version 2.6.7");

  script_tag(name:"solution", value:"Configure your PHP via the php.ini to enable 'session.use_only_cookies'.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137551");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_mandatory_keys("symphony/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"2.6.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See the solution tag for a possible Mitigation");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
