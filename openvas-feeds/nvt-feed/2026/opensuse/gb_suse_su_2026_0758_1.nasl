# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0758.1");
  script_cve_id("CVE-2026-26157", "CVE-2026-26158");
  script_tag(name:"creation_date", value:"2026-03-05 04:35:07 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-11 21:16:21 +0000 (Wed, 11 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0758-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0758-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260758-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258167");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024558.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2026:0758-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

- CVE-2026-26157: Arbitrary file overwrite and potential code execution via incomplete path sanitization (bsc#1258163).
- CVE-2026-26158: Arbitrary file modification and privilege escalation via unvalidated tar archive entries
 (bsc#1258167).");

  script_tag(name:"affected", value:"'busybox' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.37.0~150500.10.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-adduser", rpm:"busybox-adduser~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-attr", rpm:"busybox-attr~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bc", rpm:"busybox-bc~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bind-utils", rpm:"busybox-bind-utils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bzip2", rpm:"busybox-bzip2~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-coreutils", rpm:"busybox-coreutils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-cpio", rpm:"busybox-cpio~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-diffutils", rpm:"busybox-diffutils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-dos2unix", rpm:"busybox-dos2unix~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ed", rpm:"busybox-ed~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-findutils", rpm:"busybox-findutils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gawk", rpm:"busybox-gawk~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-grep", rpm:"busybox-grep~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gzip", rpm:"busybox-gzip~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-hexedit", rpm:"busybox-hexedit~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-hostname", rpm:"busybox-hostname~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iproute2", rpm:"busybox-iproute2~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iputils", rpm:"busybox-iputils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kbd", rpm:"busybox-kbd~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kmod", rpm:"busybox-kmod~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-less", rpm:"busybox-less~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-links", rpm:"busybox-links~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-man", rpm:"busybox-man~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-misc", rpm:"busybox-misc~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ncurses-utils", rpm:"busybox-ncurses-utils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-net-tools", rpm:"busybox-net-tools~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-netcat", rpm:"busybox-netcat~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-patch", rpm:"busybox-patch~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-policycoreutils", rpm:"busybox-policycoreutils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-procps", rpm:"busybox-procps~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-psmisc", rpm:"busybox-psmisc~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sed", rpm:"busybox-sed~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-selinux-tools", rpm:"busybox-selinux-tools~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sendmail", rpm:"busybox-sendmail~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sh", rpm:"busybox-sh~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sha3sum", rpm:"busybox-sha3sum~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sharutils", rpm:"busybox-sharutils~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.37.0~150500.10.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-syslogd", rpm:"busybox-syslogd~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sysvinit-tools", rpm:"busybox-sysvinit-tools~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tar", rpm:"busybox-tar~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-telnet", rpm:"busybox-telnet~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-testsuite", rpm:"busybox-testsuite~1.37.0~150500.10.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tftp", rpm:"busybox-tftp~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-time", rpm:"busybox-time~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-traceroute", rpm:"busybox-traceroute~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tunctl", rpm:"busybox-tunctl~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-udhcpc", rpm:"busybox-udhcpc~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-unzip", rpm:"busybox-unzip~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-util-linux", rpm:"busybox-util-linux~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vi", rpm:"busybox-vi~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vlan", rpm:"busybox-vlan~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-warewulf3", rpm:"busybox-warewulf3~1.37.0~150500.10.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-wget", rpm:"busybox-wget~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-which", rpm:"busybox-which~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-whois", rpm:"busybox-whois~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-xz", rpm:"busybox-xz~1.37.0~150500.7.11.1", rls:"openSUSELeap15.6"))) {
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
