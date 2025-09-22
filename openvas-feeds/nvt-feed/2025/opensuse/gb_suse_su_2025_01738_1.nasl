# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01738.1");
  script_cve_id("CVE-2024-13009", "CVE-2024-6763");
  script_tag(name:"creation_date", value:"2025-06-02 04:12:38 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 21:15:57 +0000 (Fri, 08 Nov 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01738-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01738-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501738-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243271");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039393.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jetty-minimal' package(s) announced via the SUSE-SU-2025:01738-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jetty-minimal fixes the following issues:

Upgrade to version 9.4.57.v20241219

- CVE-2024-6763: the HttpURI class does insufficient validation on the authority segment of a URI (bsc#1231652)
- CVE-2024-13009: Gzip Request Body Buffer (bsc#1243271)");

  script_tag(name:"affected", value:"'jetty-minimal' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"jetty-annotations", rpm:"jetty-annotations~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-ant", rpm:"jetty-ant~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-cdi", rpm:"jetty-cdi~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-client", rpm:"jetty-client~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-continuation", rpm:"jetty-continuation~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-deploy", rpm:"jetty-deploy~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-fcgi", rpm:"jetty-fcgi~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http", rpm:"jetty-http~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-http-spi", rpm:"jetty-http-spi~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-io", rpm:"jetty-io~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jaas", rpm:"jetty-jaas~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jmx", rpm:"jetty-jmx~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jndi", rpm:"jetty-jndi~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-jsp", rpm:"jetty-jsp~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-minimal-javadoc", rpm:"jetty-minimal-javadoc~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-openid", rpm:"jetty-openid~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-plus", rpm:"jetty-plus~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-proxy", rpm:"jetty-proxy~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-quickstart", rpm:"jetty-quickstart~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-rewrite", rpm:"jetty-rewrite~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-security", rpm:"jetty-security~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-server", rpm:"jetty-server~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-servlet", rpm:"jetty-servlet~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-servlets", rpm:"jetty-servlets~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-start", rpm:"jetty-start~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util", rpm:"jetty-util~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-util-ajax", rpm:"jetty-util-ajax~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-webapp", rpm:"jetty-webapp~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-xml", rpm:"jetty-xml~9.4.57~150200.3.31.1", rls:"openSUSELeap15.6"))) {
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
