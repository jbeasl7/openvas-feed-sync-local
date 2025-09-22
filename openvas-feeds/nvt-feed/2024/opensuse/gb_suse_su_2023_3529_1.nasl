# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833235");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-48174");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-28 18:53:37 +0000 (Mon, 28 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:42:46 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for busybox (SUSE-SU-2023:3529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3529-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T7T7KVXACGMDDER3BZQ53ZF5YN2WGWP6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox'
  package(s) announced via the SUSE-SU-2023:3529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

  * CVE-2022-48174: Fixed stack overflow vulnerability. (bsc#1214538)

  ##");

  script_tag(name:"affected", value:"'busybox' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"busybox-adduser", rpm:"busybox-adduser~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-xz", rpm:"busybox-xz~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vi", rpm:"busybox-vi~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-less", rpm:"busybox-less~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-misc", rpm:"busybox-misc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-whois", rpm:"busybox-whois~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-net-tools", rpm:"busybox-net-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-which", rpm:"busybox-which~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sed", rpm:"busybox-sed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bzip2", rpm:"busybox-bzip2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tar", rpm:"busybox-tar~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-cpio", rpm:"busybox-cpio~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-telnet", rpm:"busybox-telnet~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-syslogd", rpm:"busybox-syslogd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-unzip", rpm:"busybox-unzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-psmisc", rpm:"busybox-psmisc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-procps", rpm:"busybox-procps~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ed", rpm:"busybox-ed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-traceroute", rpm:"busybox-traceroute~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-dos2unix", rpm:"busybox-dos2unix~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-hostname", rpm:"busybox-hostname~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sendmail", rpm:"busybox-sendmail~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sysvinit-tools", rpm:"busybox-sysvinit-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-man", rpm:"busybox-man~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-findutils", rpm:"busybox-findutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bind-utils", rpm:"busybox-bind-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-netcat", rpm:"busybox-netcat~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tunctl", rpm:"busybox-tunctl~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-patch", rpm:"busybox-patch~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sh", rpm:"busybox-sh~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-links", rpm:"busybox-links~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-coreutils", rpm:"busybox-coreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bc", rpm:"busybox-bc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-grep", rpm:"busybox-grep~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gzip", rpm:"busybox-gzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sharutils", rpm:"busybox-sharutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-util-linux", rpm:"busybox-util-linux~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iproute2", rpm:"busybox-iproute2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-attr", rpm:"busybox-attr~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-wget", rpm:"busybox-wget~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-policycoreutils", rpm:"busybox-policycoreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-selinux-tools", rpm:"busybox-selinux-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-time", rpm:"busybox-time~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vlan", rpm:"busybox-vlan~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tftp", rpm:"busybox-tftp~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kmod", rpm:"busybox-kmod~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-diffutils", rpm:"busybox-diffutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gawk", rpm:"busybox-gawk~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kbd", rpm:"busybox-kbd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iputils", rpm:"busybox-iputils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ncurses-utils", rpm:"busybox-ncurses-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-testsuite", rpm:"busybox-testsuite~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-warewulf3", rpm:"busybox-warewulf3~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-adduser", rpm:"busybox-adduser~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-xz", rpm:"busybox-xz~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vi", rpm:"busybox-vi~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-less", rpm:"busybox-less~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-misc", rpm:"busybox-misc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-whois", rpm:"busybox-whois~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-net-tools", rpm:"busybox-net-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-which", rpm:"busybox-which~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sed", rpm:"busybox-sed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bzip2", rpm:"busybox-bzip2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tar", rpm:"busybox-tar~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-cpio", rpm:"busybox-cpio~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-telnet", rpm:"busybox-telnet~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-syslogd", rpm:"busybox-syslogd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-unzip", rpm:"busybox-unzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-psmisc", rpm:"busybox-psmisc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-procps", rpm:"busybox-procps~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ed", rpm:"busybox-ed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-traceroute", rpm:"busybox-traceroute~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-dos2unix", rpm:"busybox-dos2unix~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-hostname", rpm:"busybox-hostname~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sendmail", rpm:"busybox-sendmail~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sysvinit-tools", rpm:"busybox-sysvinit-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-man", rpm:"busybox-man~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-findutils", rpm:"busybox-findutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bind-utils", rpm:"busybox-bind-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-netcat", rpm:"busybox-netcat~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tunctl", rpm:"busybox-tunctl~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-patch", rpm:"busybox-patch~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sh", rpm:"busybox-sh~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-links", rpm:"busybox-links~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-coreutils", rpm:"busybox-coreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bc", rpm:"busybox-bc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-grep", rpm:"busybox-grep~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gzip", rpm:"busybox-gzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sharutils", rpm:"busybox-sharutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-util-linux", rpm:"busybox-util-linux~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iproute2", rpm:"busybox-iproute2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-attr", rpm:"busybox-attr~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-wget", rpm:"busybox-wget~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-policycoreutils", rpm:"busybox-policycoreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-selinux-tools", rpm:"busybox-selinux-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-time", rpm:"busybox-time~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vlan", rpm:"busybox-vlan~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tftp", rpm:"busybox-tftp~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kmod", rpm:"busybox-kmod~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-diffutils", rpm:"busybox-diffutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gawk", rpm:"busybox-gawk~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kbd", rpm:"busybox-kbd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iputils", rpm:"busybox-iputils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ncurses-utils", rpm:"busybox-ncurses-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-testsuite", rpm:"busybox-testsuite~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-warewulf3", rpm:"busybox-warewulf3~1.35.0~150400.3.11.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"busybox-adduser", rpm:"busybox-adduser~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-xz", rpm:"busybox-xz~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vi", rpm:"busybox-vi~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-less", rpm:"busybox-less~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-misc", rpm:"busybox-misc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-whois", rpm:"busybox-whois~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-net-tools", rpm:"busybox-net-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-which", rpm:"busybox-which~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sed", rpm:"busybox-sed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bzip2", rpm:"busybox-bzip2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tar", rpm:"busybox-tar~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-cpio", rpm:"busybox-cpio~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-telnet", rpm:"busybox-telnet~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-syslogd", rpm:"busybox-syslogd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-unzip", rpm:"busybox-unzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-psmisc", rpm:"busybox-psmisc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-procps", rpm:"busybox-procps~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ed", rpm:"busybox-ed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-traceroute", rpm:"busybox-traceroute~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-dos2unix", rpm:"busybox-dos2unix~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-hostname", rpm:"busybox-hostname~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sendmail", rpm:"busybox-sendmail~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sysvinit-tools", rpm:"busybox-sysvinit-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-man", rpm:"busybox-man~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-findutils", rpm:"busybox-findutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bind-utils", rpm:"busybox-bind-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-netcat", rpm:"busybox-netcat~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tunctl", rpm:"busybox-tunctl~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-patch", rpm:"busybox-patch~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sh", rpm:"busybox-sh~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-links", rpm:"busybox-links~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-coreutils", rpm:"busybox-coreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bc", rpm:"busybox-bc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-grep", rpm:"busybox-grep~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gzip", rpm:"busybox-gzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sharutils", rpm:"busybox-sharutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-util-linux", rpm:"busybox-util-linux~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iproute2", rpm:"busybox-iproute2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-attr", rpm:"busybox-attr~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-wget", rpm:"busybox-wget~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-policycoreutils", rpm:"busybox-policycoreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-selinux-tools", rpm:"busybox-selinux-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-time", rpm:"busybox-time~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vlan", rpm:"busybox-vlan~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tftp", rpm:"busybox-tftp~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kmod", rpm:"busybox-kmod~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-diffutils", rpm:"busybox-diffutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gawk", rpm:"busybox-gawk~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kbd", rpm:"busybox-kbd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iputils", rpm:"busybox-iputils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ncurses-utils", rpm:"busybox-ncurses-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-adduser", rpm:"busybox-adduser~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-xz", rpm:"busybox-xz~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vi", rpm:"busybox-vi~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-less", rpm:"busybox-less~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-misc", rpm:"busybox-misc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-whois", rpm:"busybox-whois~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-net-tools", rpm:"busybox-net-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-which", rpm:"busybox-which~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sed", rpm:"busybox-sed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bzip2", rpm:"busybox-bzip2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tar", rpm:"busybox-tar~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-cpio", rpm:"busybox-cpio~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-telnet", rpm:"busybox-telnet~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-syslogd", rpm:"busybox-syslogd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-unzip", rpm:"busybox-unzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-psmisc", rpm:"busybox-psmisc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-procps", rpm:"busybox-procps~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ed", rpm:"busybox-ed~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-traceroute", rpm:"busybox-traceroute~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-dos2unix", rpm:"busybox-dos2unix~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-hostname", rpm:"busybox-hostname~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sendmail", rpm:"busybox-sendmail~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sysvinit-tools", rpm:"busybox-sysvinit-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-man", rpm:"busybox-man~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-findutils", rpm:"busybox-findutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bind-utils", rpm:"busybox-bind-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-netcat", rpm:"busybox-netcat~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tunctl", rpm:"busybox-tunctl~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-patch", rpm:"busybox-patch~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sh", rpm:"busybox-sh~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-links", rpm:"busybox-links~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-coreutils", rpm:"busybox-coreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-bc", rpm:"busybox-bc~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-grep", rpm:"busybox-grep~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gzip", rpm:"busybox-gzip~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-sharutils", rpm:"busybox-sharutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-util-linux", rpm:"busybox-util-linux~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iproute2", rpm:"busybox-iproute2~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-attr", rpm:"busybox-attr~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-wget", rpm:"busybox-wget~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-policycoreutils", rpm:"busybox-policycoreutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-selinux-tools", rpm:"busybox-selinux-tools~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-time", rpm:"busybox-time~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-vlan", rpm:"busybox-vlan~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-tftp", rpm:"busybox-tftp~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kmod", rpm:"busybox-kmod~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-diffutils", rpm:"busybox-diffutils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-gawk", rpm:"busybox-gawk~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-kbd", rpm:"busybox-kbd~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-iputils", rpm:"busybox-iputils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-ncurses-utils", rpm:"busybox-ncurses-utils~1.35.0~150400.4.5.1", rls:"openSUSELeap15.5"))) {
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