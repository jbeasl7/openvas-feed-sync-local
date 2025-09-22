# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833101");
  script_version("2025-02-26T05:38:40+0000");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-23816", "CVE-2022-23825", "CVE-2022-26362", "CVE-2022-26363", "CVE-2022-26364", "CVE-2022-29900", "CVE-2022-33745");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-02 18:33:16 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 08:05:26 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xen (SUSE-SU-2022:2599-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2599-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RSP3EQ6WE46JI7XQGMWB5BZDZ4C24GZM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the SUSE-SU-2022:2599-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  - CVE-2022-26363, CVE-2022-26364: Fixed insufficient care with
       non-coherent mappings (XSA-402) (bsc#1199966).

  - CVE-2022-21123, CVE-2022-21125, CVE-2022-21166: Fixed MMIO stale data
       vulnerabilities on x86 (XSA-404) (bsc#1200549).

  - CVE-2022-26362: Fixed a race condition in typeref acquisition (XSA-401)
       (bsc#1199965).

  - CVE-2022-33745: Fixed insufficient TLB flush for x86 PV guests in shadow
       mode (XSA-408) (bsc#1201394).

  - CVE-2022-23816, CVE-2022-23825, CVE-2022-29900: Fixed RETBLEED
       vulnerability, arbitrary speculative code execution with return
       instructions (XSA-407) (bsc#1201469).
  Fixed several upstream bugs (bsc#1027519).
  Special Instructions and Notes:
  Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap Micro 5.2.");

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

if(release == "openSUSELeapMicro5.2") {

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.14.5_04~150300.3.32.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.14.5_04~150300.3.32.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.14.5_04~150300.3.32.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.14.5_04~150300.3.32.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.14.5_04~150300.3.32.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.14.5_04~150300.3.32.1", rls:"openSUSELeapMicro5.2"))) {
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