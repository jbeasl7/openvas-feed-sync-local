# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomee";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810965");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-06-28 17:04:45 +0530 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2016-0779");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache TomEE RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomee_server_detect.nasl");
  script_mandatory_keys("apache/tomee/detected");

  script_tag(name:"summary", value:"Apache TomEE is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  EjbObjectInputStream class related to EJBd protocol.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via a crafted serialized object.");

  script_tag(name:"affected", value:"Apache TomEE before 1.7.4 and 7.x before 7.0.0-M3.

  Note: This issue only affects you if you rely on EJBd protocol
  (proprietary remote EJB protocol). This one is not activated by
  default on the 7.x series but it was on the 1.x ones.");

  script_tag(name:"solution", value:"Upgrade to version 1.7.4 or 7.0.0-M3 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/537806/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84422");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q1/649");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.7.4"))
  fix = "1.7.4";
else if (version =~ "^7") {
  if (revcomp(a: version, b: "7.0.0.M3") < 0)
    fix = "7.0.0-M3";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
