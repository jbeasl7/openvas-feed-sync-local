# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:spring_boot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113882");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-04-06 08:06:40 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 17:43:00 +0000 (Fri, 08 Apr 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-22965");

  script_name("VMware Spring Boot RCE Vulnerability (Spring4Shell, SpringShell)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_spring_boot_consolidation.nasl");
  script_mandatory_keys("vmware/spring/boot/detected");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22965");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-boot-2-6-6-available-now");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-boot-2-5-12-available-now");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement#suggested-workarounds");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/04/01/spring-framework-rce-mitigation-alternative");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/5grm3b0g6co2rcw3tov34vx8r3ws9x6y");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/k1oknlyc28x25k3tnr9chr8wc37yrxlw");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/4318xzl2f9o8j3x56gx46vlst5myroc0");
  script_xref(name:"URL", value:"https://www.praetorian.com/blog/spring-core-jdk9-rce/");
  script_xref(name:"URL", value:"https://blog.sonatype.com/new-0-day-spring-framework-vulnerability-confirmed");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/");
  script_xref(name:"URL", value:"https://bugalert.org/content/notices/2022-03-30-spring.html");
  script_xref(name:"URL", value:"https://www.intruder.io/blog/spring4shell-cve-2022-22965");
  script_xref(name:"URL", value:"https://twitter.com/RandoriAttack/status/1509298490106593283");
  script_xref(name:"URL", value:"https://github.com/alt3kx/CVE-2022-22965");

  script_tag(name:"summary", value:"VMware Spring Boot is prone to a remote code execution (RCE)
  vulnerability in the used Spring Framework dubbed 'Spring4Shell' or 'SpringShell'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A Spring MVC or Spring WebFlux application running on JDK 9+ may
  be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the
  application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot
  executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the
  vulnerability is more general, and there may be other ways to exploit it.");

  script_tag(name:"affected", value:"VMware Spring Boot versions prior to 2.5.12 and 2.6.x prior to
  2.6.6.

  The following are the requirements for an environment to be affected to this specific
  vulnerability:

  - Running on JDK 9 or higher

  - Apache Tomcat as the Servlet container

  - Packaged as a traditional WAR and deployed in a standalone Tomcat instance. Typical Spring Boot
  deployments using an embedded Servlet container or reactive web server are not impacted.

  - spring-webmvc or spring-webflux dependency

  - an affected version of Spring Boot");

  script_tag(name:"solution", value:"Update to Spring Boot version 2.5.12, 2.6.6 or later which
  updates to Spring Framework version 5.3.18 or later.

  Possible mitigations without doing an update:

  - Upgrading Tomcat (10.0.20, 9.0.62 or 8.5.78 hardened the class loader to provide a mitigation)

  - Downgrading to Java 8

  - Disallowed Fields

  Please see the references for more information on these mitigation possibilities.");

  # nb: Apps / systems are only affected when running on Tomcat with additional constraints like
  # being a Web MVC or WebFlux application...
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.5.12" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.5.12/2.6.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"2.6.0", test_version_up:"2.6.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.6.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
