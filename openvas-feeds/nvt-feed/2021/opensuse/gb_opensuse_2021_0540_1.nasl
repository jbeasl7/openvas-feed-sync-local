# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853751");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:50 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for openSUSE (openSUSE-SU-2021:0540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0540-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/F2VEM2YB6B6WI54XARQNZJEY3DGFDRCD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openSUSE'
  package(s) announced via the openSUSE-SU-2021:0540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for various openSUSE kernel related packages refreshes them
     with the new UEFI Secure boot key.");

  script_tag(name:"affected", value:"'openSUSE' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"dpdk-doc-19.11.4", rpm:"dpdk-doc-19.11.4~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-autoload-0.12.5", rpm:"v4l2loopback-autoload-0.12.5~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v4l2loopback-utils-0.12.5", rpm:"v4l2loopback-utils-0.12.5~lp152.2.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons-6.1.18", rpm:"virtualbox-guest-desktop-icons-6.1.18~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source-6.1.18", rpm:"virtualbox-guest-source-6.1.18~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source-6.1.18", rpm:"virtualbox-host-source-6.1.18~lp152.2.18.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-0.8", rpm:"bbswitch-0.8~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-debugsource-0.8", rpm:"bbswitch-debugsource-0.8~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-default-0.8.k5.3.18.lp152.69", rpm:"bbswitch-kmp-default-0.8.k5.3.18.lp152.69~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-default-debuginfo-0.8.k5.3.18.lp152.69", rpm:"bbswitch-kmp-default-debuginfo-0.8.k5.3.18.lp152.69~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-preempt-0.8.k5.3.18.lp152.69", rpm:"bbswitch-kmp-preempt-0.8.k5.3.18.lp152.69~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bbswitch-kmp-preempt-debuginfo-0.8.k5.3.18._lp152.69", rpm:"bbswitch-kmp-preempt-debuginfo-0.8.k5.3.18._lp152.69~lp152.6.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-7.2.8", rpm:"crash-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debuginfo-7.2.8", rpm:"crash-debuginfo-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-debugsource-7.2.8", rpm:"crash-debugsource-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-devel-7.2.8", rpm:"crash-devel-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-doc-7.2.8", rpm:"crash-doc-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-eppic-7.2.8", rpm:"crash-eppic-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-eppic-debuginfo-7.2.8", rpm:"crash-eppic-debuginfo-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-gcore-7.2.8", rpm:"crash-gcore-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-gcore-debuginfo-7.2.8", rpm:"crash-gcore-debuginfo-7.2.8~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default-7.2.8.k5.3.18.lp152.69", rpm:"crash-kmp-default-7.2.8.k5.3.18.lp152.69~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-default-debuginfo-7.2.8.k5.3.18.lp152.69", rpm:"crash-kmp-default-debuginfo-7.2.8.k5.3.18.lp152.69~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-preempt-7.2.8.k5.3.18.lp152.69", rpm:"crash-kmp-preempt-7.2.8.k5.3.18.lp152.69~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crash-kmp-preempt-debuginfo-7.2.8.k5.3.18.lp152.69", rpm:"crash-kmp-preempt-debuginfo-7.2.8.k5.3.18.lp152.69~lp152.3.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

   if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kmp-preempt-debuginfo", rpm:"xtables-addons-kmp-preempt-debuginfo~3.9_k5.3.18_lp152.69~lp152.2.6.1", rls:"openSUSELeap15.2"))) {
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
