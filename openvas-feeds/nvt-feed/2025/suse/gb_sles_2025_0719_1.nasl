# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0719.1");
  script_cve_id("CVE-2020-13936");
  script_tag(name:"creation_date", value:"2025-02-28 04:07:20 +0000 (Fri, 28 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-16 16:19:36 +0000 (Tue, 16 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0719-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0719-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250719-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020436.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Maven' package(s) announced via the SUSE-SU-2025:0719-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Maven fixes the following issues:

maven-dependency-analyzer was updated from version 1.13.2 to 1.15.1:

- Key changes across versions:
 * Bug fixes and improved support of dynamic types
 * Dependency upgrades (ASM, Maven core, and notably the removal of commons-io)
 * Improved error handling by logging instead of failing
 * Improved dependency usage tracking

maven-dependency-plugin was updated from version 3.6.0 to 3.8.1:

- Key changes across versions:
 * Dependency upgrades on maven-dependency-analyzer and Doxia
 * Deprecated dependency:sources in favor of dependency:resolve-sources
 * Documentation improvements
 * New dependency analysis goal to check for invalid exclusions
 * New JSON output option for dependency:tree
 * Performance improvements
 * Several bug fixes addressing:
 + The handling of silent parameters
 + The display of the optional flag in the tree
 + The clarity of some error messages

maven-doxia-sitetools was updated from version 1.11.1 to 2.0.0:

- Key changes across versions:
 * New features:
 + Passing the input filename to the parser
 + Adding a timezone field to the site descriptor
 + Configuring parsers per markup
 * Improvements:
 + Clarifying site descriptor properties
 + Requiring a skin if a site descriptor (site.xml) has been provided
 + Optimization of resource handling
 + Overhauled locale support
 + Refinined menu item display
 + Use of Maven Resolver for artifact resolution
 + Enhanced Velocity context population
 + Automating anchor creation
 * Internal changes:
 + Migration from Plexus to Sisu
 + Upgraded to Java 8
 + Removal of deprecated components and features (such as Maven 1.x support, Google-related properties)
 + Simplified the site model
 + Improved the DocumentRenderer interface/DocumentRenderingContext class API
 * Several bug fixes addressing:
 + The Plexus to Sisu migration
 + Decoration model injection
 + Anchor creation
 + XML character escaping
 + Handling of 0-byte site descriptors

maven-doxia was updated from version 1.12.0 to 2.0.0:

- Key changes across versions:
 * Improved HTML5 Support:
 + Obsolete attributes and elements were removed
 + CSS styles are now used for styling
 + XHTML5 is now the default HTML implementation, and XHTML(4) is deprecated
 * Improved Markdown Support:
 + A new Markdown sink allows converting content to Markdown.
 + Support for various Markdown features like blockquotes, footnotes, and metadata has been added
 * General Improvements:
 + Dependencies were updated
 + Doxia was upgraded to Java 8
 + Logging and Doxia ID generation were streamlined
 + Migration from Plexus to Sisu
 + Removed deprecated modules and code
 * Several bug fixes addressing:
 + HTML5 incorrect output such as tables, styling and missing or improperly handled attributes
 + Markdown formatting issues
 + Issues with plexus migration
 + Incorrect generation of unique IDs
 + Incorrect anchor generation ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Maven' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-core", rpm:"maven-doxia-core~2.0.0~150200.4.18.11", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-apt", rpm:"maven-doxia-module-apt~2.0.0~150200.4.18.11", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fml", rpm:"maven-doxia-module-fml~2.0.0~150200.4.18.11", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xdoc", rpm:"maven-doxia-module-xdoc~2.0.0~150200.4.18.11", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml5", rpm:"maven-doxia-module-xhtml5~2.0.0~150200.4.18.11", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sink-api", rpm:"maven-doxia-sink-api~2.0.0~150200.4.18.11", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sitetools", rpm:"maven-doxia-sitetools~2.0.0~150200.3.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-invoker", rpm:"maven-invoker~3.3.0~150200.3.7.5", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc-plugin", rpm:"maven-javadoc-plugin~3.11.1~150200.4.21.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-plugin-annotations", rpm:"maven-plugin-annotations~3.15.1~150200.3.15.12", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-reporting-api", rpm:"maven-reporting-api~4.0.0~150200.3.10.12", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~3.5.2~150200.3.9.20.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plexus-velocity", rpm:"plexus-velocity~2.1.0~150200.3.10.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"velocity-engine-core", rpm:"velocity-engine-core~2.4~150200.5.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-core", rpm:"maven-doxia-core~2.0.0~150200.4.18.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-apt", rpm:"maven-doxia-module-apt~2.0.0~150200.4.18.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fml", rpm:"maven-doxia-module-fml~2.0.0~150200.4.18.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xdoc", rpm:"maven-doxia-module-xdoc~2.0.0~150200.4.18.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml5", rpm:"maven-doxia-module-xhtml5~2.0.0~150200.4.18.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sink-api", rpm:"maven-doxia-sink-api~2.0.0~150200.4.18.11", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sitetools", rpm:"maven-doxia-sitetools~2.0.0~150200.3.18.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-invoker", rpm:"maven-invoker~3.3.0~150200.3.7.5", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc-plugin", rpm:"maven-javadoc-plugin~3.11.1~150200.4.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-plugin-annotations", rpm:"maven-plugin-annotations~3.15.1~150200.3.15.12", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-reporting-api", rpm:"maven-reporting-api~4.0.0~150200.3.10.12", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~3.5.2~150200.3.9.20.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plexus-velocity", rpm:"plexus-velocity~2.1.0~150200.3.10.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"velocity-engine-core", rpm:"velocity-engine-core~2.4~150200.5.3.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-core", rpm:"maven-doxia-core~2.0.0~150200.4.18.11", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-apt", rpm:"maven-doxia-module-apt~2.0.0~150200.4.18.11", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fml", rpm:"maven-doxia-module-fml~2.0.0~150200.4.18.11", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xdoc", rpm:"maven-doxia-module-xdoc~2.0.0~150200.4.18.11", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml5", rpm:"maven-doxia-module-xhtml5~2.0.0~150200.4.18.11", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sink-api", rpm:"maven-doxia-sink-api~2.0.0~150200.4.18.11", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sitetools", rpm:"maven-doxia-sitetools~2.0.0~150200.3.18.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-invoker", rpm:"maven-invoker~3.3.0~150200.3.7.5", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc-plugin", rpm:"maven-javadoc-plugin~3.11.1~150200.4.21.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-plugin-annotations", rpm:"maven-plugin-annotations~3.15.1~150200.3.15.12", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-reporting-api", rpm:"maven-reporting-api~4.0.0~150200.3.10.12", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire", rpm:"maven-surefire~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-plugin", rpm:"maven-surefire-plugin~3.5.2~150200.3.9.20.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-junit", rpm:"maven-surefire-provider-junit~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-surefire-provider-testng", rpm:"maven-surefire-provider-testng~3.5.2~150200.3.9.20.12", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plexus-velocity", rpm:"plexus-velocity~2.1.0~150200.3.10.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"velocity-engine-core", rpm:"velocity-engine-core~2.4~150200.5.3.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
