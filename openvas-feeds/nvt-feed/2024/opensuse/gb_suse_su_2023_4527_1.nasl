# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833618");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:56:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for maven, maven (SUSE-SU-2023:4527-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4527-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZVHFV4ASLTFF4BRGDZJ5BFB5IMENJKEQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maven, maven'
  package(s) announced via the SUSE-SU-2023:4527-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for maven, maven-resolver, sbt, xmvn fixes the following issues:

  * CVE-2023-46122: Fixed an arbitrary file write when extracting a crafted zip
      file with sbt (bsc#1216529).

  * Upgraded maven to version 3.9.4

  * Upgraded maven-resolver to version 1.9.15");

  script_tag(name:"affected", value:"'maven, maven' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.4~150200.4.18.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.4~150200.4.18.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-classpath", rpm:"maven-resolver-transport-classpath~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc", rpm:"maven-javadoc~3.9.4~150200.4.18.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-javadoc", rpm:"maven-resolver-javadoc~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-test-util", rpm:"maven-resolver-test-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt", rpm:"sbt~0.13.18~150200.4.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt-bootstrap", rpm:"sbt-bootstrap~0.13.18~150200.4.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector-javadoc", rpm:"xmvn-connector-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-tools-javadoc", rpm:"xmvn-tools-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-parent", rpm:"xmvn-parent~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver", rpm:"maven-resolver~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo-javadoc", rpm:"xmvn-mojo-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.4~150200.4.18.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.4~150200.4.18.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-classpath", rpm:"maven-resolver-transport-classpath~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc", rpm:"maven-javadoc~3.9.4~150200.4.18.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-javadoc", rpm:"maven-resolver-javadoc~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-test-util", rpm:"maven-resolver-test-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt", rpm:"sbt~0.13.18~150200.4.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt-bootstrap", rpm:"sbt-bootstrap~0.13.18~150200.4.16.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector-javadoc", rpm:"xmvn-connector-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-tools-javadoc", rpm:"xmvn-tools-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-parent", rpm:"xmvn-parent~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver", rpm:"maven-resolver~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.15~150200.3.14.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo-javadoc", rpm:"xmvn-mojo-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.4~150200.4.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.4~150200.4.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-classpath", rpm:"maven-resolver-transport-classpath~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc", rpm:"maven-javadoc~3.9.4~150200.4.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-javadoc", rpm:"maven-resolver-javadoc~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-test-util", rpm:"maven-resolver-test-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt", rpm:"sbt~0.13.18~150200.4.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt-bootstrap", rpm:"sbt-bootstrap~0.13.18~150200.4.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector-javadoc", rpm:"xmvn-connector-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-tools-javadoc", rpm:"xmvn-tools-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-parent", rpm:"xmvn-parent~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver", rpm:"maven-resolver~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo-javadoc", rpm:"xmvn-mojo-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.4~150200.4.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.4~150200.4.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-classpath", rpm:"maven-resolver-transport-classpath~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc", rpm:"maven-javadoc~3.9.4~150200.4.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-javadoc", rpm:"maven-resolver-javadoc~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-test-util", rpm:"maven-resolver-test-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt", rpm:"sbt~0.13.18~150200.4.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbt-bootstrap", rpm:"sbt-bootstrap~0.13.18~150200.4.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector-javadoc", rpm:"xmvn-connector-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-tools-javadoc", rpm:"xmvn-tools-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-parent", rpm:"xmvn-parent~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver", rpm:"maven-resolver~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.15~150200.3.14.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo-javadoc", rpm:"xmvn-mojo-javadoc~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.14.1", rls:"openSUSELeap15.5"))) {
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
