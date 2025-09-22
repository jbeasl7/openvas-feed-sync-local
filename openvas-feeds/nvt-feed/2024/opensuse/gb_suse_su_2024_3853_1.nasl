# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856674");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-24795");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-01 05:03:02 +0000 (Fri, 01 Nov 2024)");
  script_name("openSUSE: Security Advisory for uwsgi (SUSE-SU-2024:3853-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3853-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GDIAJ27VL2K243BWSBUC7E6Y4HBYRCG7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'uwsgi'
  package(s) announced via the SUSE-SU-2024:3853-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for uwsgi fixes the following issues:

  * CVE-2024-24795: Fixed HTTP Response Splitting in multiple modules
      (bsc#1222332)");

  script_tag(name:"affected", value:"'uwsgi' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-sqlite3-debuginfo", rpm:"uwsgi-sqlite3-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-debuginfo", rpm:"uwsgi-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-ldap", rpm:"uwsgi-ldap~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-pypy-debuginfo", rpm:"uwsgi-pypy-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi", rpm:"uwsgi~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-python3", rpm:"uwsgi-python3~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-glusterfs", rpm:"uwsgi-glusterfs~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-libffi-debuginfo", rpm:"uwsgi-libffi-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-pypy", rpm:"uwsgi-pypy~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-emperor-pg", rpm:"uwsgi-emperor-pg~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-logzmq", rpm:"uwsgi-logzmq~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-xslt", rpm:"uwsgi-xslt~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-emperor-zeromq", rpm:"uwsgi-emperor-zeromq~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-lua-debuginfo", rpm:"uwsgi-lua-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-sqlite3", rpm:"uwsgi-sqlite3~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-python3-debuginfo", rpm:"uwsgi-python3-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-php7-debuginfo", rpm:"uwsgi-php7-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-jvm", rpm:"uwsgi-jvm~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-php7", rpm:"uwsgi-php7~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-debugsource", rpm:"uwsgi-debugsource~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-greenlet-debuginfo", rpm:"uwsgi-greenlet-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-logzmq-debuginfo", rpm:"uwsgi-logzmq-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-emperor-zeromq-debuginfo", rpm:"uwsgi-emperor-zeromq-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod-uwsgi-debuginfo", rpm:"apache2-mod-uwsgi-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-libffi", rpm:"uwsgi-libffi~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-python", rpm:"uwsgi-python~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-psgi", rpm:"uwsgi-psgi~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-lua", rpm:"uwsgi-lua~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-pam-debuginfo", rpm:"uwsgi-pam-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-gevent", rpm:"uwsgi-gevent~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-psgi-debuginfo", rpm:"uwsgi-psgi-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-emperor-pg-debuginfo", rpm:"uwsgi-emperor-pg-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-python-debuginfo", rpm:"uwsgi-python-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-pam", rpm:"uwsgi-pam~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-xslt-debuginfo", rpm:"uwsgi-xslt-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-greenlet", rpm:"uwsgi-greenlet~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod.uwsgi", rpm:"apache2-mod.uwsgi~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-glusterfs-debuginfo", rpm:"uwsgi-glusterfs-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-gevent-debuginfo", rpm:"uwsgi-gevent-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-jvm-debuginfo", rpm:"uwsgi-jvm-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwsgi-ldap-debuginfo", rpm:"uwsgi-ldap-debuginfo~2.0.19.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
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
