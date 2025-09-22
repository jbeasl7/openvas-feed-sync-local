# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1838.1");
  script_cve_id("CVE-2015-3218", "CVE-2015-3255", "CVE-2015-3256", "CVE-2015-4625");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1838-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1838-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151838-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950114");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-October/001649.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit' package(s) announced via the SUSE-SU-2015:1838-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"polkit was updated to the 0.113 release, fixing security issues and bugs.

Security issues fixed:
* Fixes CVE-2015-4625, a local privilege escalation due to predictable
 authentication session cookie values. Thanks to Tavis Ormandy, Google Project
 Zero for reporting this issue. For the future, authentication agents are
 encouraged to use PolkitAgentSession instead of using the D-Bus agent response
 API directly. (bsc#935119)
* Fixes CVE-2015-3256, various memory corruption vulnerabilities in use of the
 JavaScript interpreter, possibly leading to local privilege escalation.
 (bsc#943816)
* Fixes CVE-2015-3255, a memory corruption vulnerability in handling duplicate
 action IDs, possibly leading to local privilege escalation. Thanks to
 Laurent Bigonville for reporting this issue. (bsc#939246)
* Fixes CVE-2015-3218, which allowed any local user to crash polkitd. Thanks to
 Tavis Ormandy, Google Project Zero, for reporting this issue. (bsc#933922)

Other issues fixed:
* On systemd-213 and later, the 'active' state is shared across all sessions of
 an user, instead of being tracked separately.
* pkexec, when not given a program to execute, runs the users shell by
 default.
* Fixed shutdown problems on powerpc64le (bsc#950114)
* polkit had a memory leak (bsc#912889)");

  script_tag(name:"affected", value:"'polkit' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libpolkit0", rpm:"libpolkit0~0.113~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.113~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Polkit-1_0", rpm:"typelib-1_0-Polkit-1_0~0.113~4.1", rls:"SLES12.0"))) {
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
