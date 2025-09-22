# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107199");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-05-22 17:05:17 +0200 (Mon, 22 May 2017)");
  script_cve_id("CVE-2017-7464");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");
  script_name("Red Hat JBoss Enterprise Application Platform (EAP) 7.x XXE Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_http_detect.nasl");
  script_mandatory_keys("redhat/jboss/eap/detected");

  script_tag(name:"summary", value:"Red Hat JBoss Enterprise Application Platform (EAP) is prone to
  an XML external entity (XXE) injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When parsing XML which does entity expansion the
  SAXParserFactory used in EAP expands external entities, even when
  XMLConstants.FEATURE_SECURE_PROCESSING is set to true.");

  script_tag(name:"impact", value:"Attackers can exploit this  issue to gain access to sensitive
  information or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Red Hat JBoss EAP 7.x.");

  script_tag(name:"solution", value:"Enable the security features of the DocumentBuilderFactory or
  SaxParserFactory as described by OWASP in the references.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2017-7464");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2017-7464");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98450");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^7(\.[0-9]+|$)") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Mitigation");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
