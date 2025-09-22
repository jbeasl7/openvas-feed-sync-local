# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812525");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2017-5660");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-02-28 12:10:48 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-21 16:16:00 +0000 (Wed, 21 Mar 2018)");
  script_name("Apache Traffic Server (ATS) Host Header and Line Folding Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Host
  header and line folding.  This can have issues when interacting with upstream
  proxies and the wrong host being used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain unauthorized access to certain resources. This may aid
  in further attacks.");

  script_tag(name:"affected", value:"Apache Traffic Server 6.2.0 and prior.

  Apache Traffic Server 7.0.0");

  script_tag(name:"solution", value:"Upgrade to 6.2.2, 7.1.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q1/196");
  script_xref(name:"URL", value:"https://github.com/apache/trafficserver/pull/1657");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "7.0.0")
  fix = "7.1.2";

else if(version_is_less(version:vers, test_version: "6.2.0"))
  fix =  "6.2.2";

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path:path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
