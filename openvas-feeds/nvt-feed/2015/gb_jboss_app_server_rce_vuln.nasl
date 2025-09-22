# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redhat:jboss_wildfly_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806623");
  script_version("2024-12-03T05:05:44+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-12-03 05:05:44 +0000 (Tue, 03 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-11-17 16:28:17 +0530 (Tue, 17 Nov 2015)");
  script_name("JBoss WildFly <= 9.0.2 RCE Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("sw_redhat_wildfly_http_detect.nasl");
  script_mandatory_keys("redhat/wildfly/detected");

  script_xref(name:"URL", value:"https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#jboss");
  script_xref(name:"URL", value:"https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/jboss-jmxinvoker-exploit.request");

  script_tag(name:"summary", value:"JBoss WildFly is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to presence of a deserialization error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the affected system.");

  script_tag(name:"affected", value:"JBoss WildFly versions 9.0.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  # nb: Unclear why this has been used in the past. Probably because one or both of these could apply:
  # - it's not fully clear if JBoss WildFly was actually affected at all (only JBoss Application
  # Server is mentioned in the advisory which has been superseded by JBoss/RedHat WildFly).
  # - the current existing HTTP detection is only extracting a major version like e.g. "9"
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"9.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
