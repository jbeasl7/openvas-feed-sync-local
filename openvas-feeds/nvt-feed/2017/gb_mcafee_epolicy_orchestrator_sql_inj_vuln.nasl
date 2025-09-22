# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106681");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-03-22 13:37:15 +0700 (Wed, 22 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:01:00 +0000 (Thu, 07 Mar 2019)");

  script_cve_id("CVE-2016-8027");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("McAfee ePolicy Orchestrator SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to a blind SQL injection
vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable blind SQL injection vulnerability exists within ePolicy
Orchestrator. A specially crafted HTTP post can allow an attacker to alter a SQL query, which can result in
disclosure of information within the database or impersonation of an agent without authentication.");

  script_tag(name:"affected", value:"ePO versions 5.1.3, 5.3.2 and prior.");

  script_tag(name:"solution", value:"Apply the appropriate hotfix.");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10187");
  script_xref(name:"URL", value:"http://blog.talosintelligence.com/2017/02/vulnerability-spotlight-mcafee-epolicy.html");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0229/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

build = get_kb_item("mcafee_ePO/build");

if (version_is_less(version: version, test_version: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3 build 188");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.1.3")) {
  if (build && version_is_greater_equal(version: build, test_version: "188"))
    exit(99);

  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3 build 188");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
