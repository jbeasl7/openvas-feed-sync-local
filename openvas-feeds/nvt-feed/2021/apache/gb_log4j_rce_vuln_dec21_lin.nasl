# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:log4j";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147345");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-12-16 06:59:43 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-06 13:45:00 +0000 (Thu, 06 Jan 2022)");

  script_cve_id("CVE-2021-4104");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Apache Log4j 1.2.x RCE Vulnerability (Linux/Unix, Dec 2021) - Version Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_log4j_consolidation.nasl");
  script_mandatory_keys("apache/log4j/ssh-login/detected");

  script_tag(name:"summary", value:"Apache Log4j is prone to a remote code execution (RCE)
  vulnerability in JMSAppender.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"JMSAppender in Log4j 1.2 is vulnerable to deserialization of
  untrusted data when the attacker has write access to the Log4j configuration. The attacker can
  provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender
  to perform JNDI requests that result in remote code execution in a similar fashion to
  CVE-2021-44228.

  Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is
  not the default.");

  script_tag(name:"affected", value:"Apache Log4j version 1.2.x.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it
  addresses numerous other issues from the previous versions.");

  script_xref(name:"URL", value:"https://github.com/apache/logging-log4j2/pull/608#issuecomment-990494126");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^1\.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
