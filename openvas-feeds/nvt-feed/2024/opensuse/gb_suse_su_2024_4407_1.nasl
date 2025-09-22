# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856878");
  script_cve_id("CVE-2024-47535");
  script_tag(name:"creation_date", value:"2024-12-24 05:00:28 +0000 (Tue, 24 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4407-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4407-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244407-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233297");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/020044.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aalto-xml, flatten-maven-plugin, jctools, moditect, netty, netty-tcnative' package(s) announced via the SUSE-SU-2024:4407-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aalto-xml, flatten-maven-plugin, jctools, moditect, netty, netty-tcnative fixes the following issues:

- CVE-2024-47535: Fixed unsafe reading of large environment files when Netty is loaded by a java application can
lead to a crash due to the JVM memory limit being exceeded in netty (bsc#1233297)

Other fixes:
- Upgraded netty to upstream version 4.1.115
- Upgraded netty-tcnative to version 2.0.69 Final
- Updated jctools to version 4.0.5
- Updated aalto-xml to version 1.3.3
- Updated moditect to version 1.2.2
- Updated flatten-maven-plugin to version 1.6.0");

  script_tag(name:"affected", value:"'aalto-xml, flatten-maven-plugin, jctools, moditect, netty, netty-tcnative' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"jctools", rpm:"jctools~4.0.5~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jctools-channels", rpm:"jctools-channels~4.0.5~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jctools-experimental", rpm:"jctools-experimental~4.0.5~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jctools-javadoc", rpm:"jctools-javadoc~4.0.5~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.115~150200.4.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.115~150200.4.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.69~150200.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative-javadoc", rpm:"netty-tcnative-javadoc~2.0.69~150200.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"jctools", rpm:"jctools~4.0.5~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jctools-channels", rpm:"jctools-channels~4.0.5~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jctools-experimental", rpm:"jctools-experimental~4.0.5~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jctools-javadoc", rpm:"jctools-javadoc~4.0.5~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.115~150200.4.26.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.115~150200.4.26.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.69~150200.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative-javadoc", rpm:"netty-tcnative-javadoc~2.0.69~150200.3.22.1", rls:"openSUSELeap15.6"))) {
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
