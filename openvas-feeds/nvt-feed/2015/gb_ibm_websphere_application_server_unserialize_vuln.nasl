# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806624");
  script_version("2024-12-03T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-12-03 05:05:44 +0000 (Tue, 03 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-11-17 17:28:17 +0530 (Tue, 17 Nov 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:02:03 +0000 (Wed, 24 Jul 2024)");

  script_cve_id("CVE-2015-7450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server RCE Vulnerability (Nov 2015) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a remote code
  execution (RCE) vulnerability in Apache Commons Collections.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to presence of a deserialization error.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions:

  - 16.0.0.2 through 17.0.0.3 (Liberty)

  - 8.5.0.0 through 8.5.5.7 (Liberty)

  - 8.5.0.0 through 8.5.5.7 (Traditional)

  - 8.0.0.0 through 8.0.0.11 (Traditional)

  - 7.0.0.0 through 7.0.0.39 (Traditional)

  Notes:

  - Liberty in all versions is only actively exploitable if using the optional EJB Embeddable
    Container and JPAClient features

  - Liberty versions 8.5.0.0 through 8.5.5.7 only enables the Apache Commons Collections and thus
    exploitable if one of the jsf-2.0, jsf-2.2 or jpa-2.0 features are enabled");

  script_tag(name:"solution", value:"Updates and mitigations are available. Please see the
  references or vendor advisory for more information.

  Note: Please create an override for this result if only the mitigation / an interim fix was
  applied");

  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-vulnerability-apache-commons-affects-ibm-websphere-application-server-cve-2015-7450");
  script_xref(name:"URL", value:"https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/");
  script_xref(name:"URL", value:"https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/websphere-soap-exploit.request");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122210651/http://www.securityfocus.com/bid/77653");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (get_kb_item("ibm/websphere/liberty/detected")) {

  if (version_in_range(version: version, test_version: "8.5.0.0", test_version2: "8.5.5.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.8 / Interim Fix PI52103");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "16.0.0.2", test_version2: "17.0.0.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.0.0.4 / Interim Fix PI52103");
    security_message(port: 0, data: report);
    exit(0);
  }
}

else {

  if (version_in_range(version: version, test_version: "7.0.0.0", test_version2: "7.0.0.39")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.41 / Interim Fix PI52103");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.12 / Interim Fix PI52103");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "8.5.0.0", test_version2: "8.5.5.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.8 / Interim Fix PI52103");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
