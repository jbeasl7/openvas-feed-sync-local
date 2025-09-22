# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zarafa:zarafa_collaboration_platform";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805708");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-07-03 15:19:25 +0530 (Fri, 03 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_cve_id("CVE-2015-3436");
  script_name("Zarafa Collaboration Platform Arbitrary File Access Vulnerability");

  script_tag(name:"summary", value:"Zarafa Collaboration Platform is prone to an arbitrary file access vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to
  'provider/server/ECServer.cpp' allows local users to write to arbitrary
  files via a symlink attack on '/tmp/zarafa-upgrade-lock'");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to retrieve or delete arbitrary files, which may aid in further
  attacks.");

  script_tag(name:"affected", value:"Zarafa Collaboration Platform (ZCP)
  before 7.1.13 and 7.2.x before 7.2.1");

  script_tag(name:"solution", value:"Upgrade to 7.1.13 or 7.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://jira.zarafa.com/browse/ZCP-13282");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2015-June/159497.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_zarafa_webapp_detect.nasl");
  script_mandatory_keys("zarafa_zcp/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"7.1.13")) {
  fix = "7.1.13";
  vuln = TRUE;
}

if(version =~ "^7\.2") {
  if(version_is_less(version:version, test_version:"7.2.1")) {
    fix = "7.2.1";
    vuln = TRUE;
  }
}

if(vuln) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
