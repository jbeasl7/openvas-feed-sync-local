# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833323");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-26437");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-10 18:59:48 +0000 (Mon, 10 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for pdns (openSUSE-SU-2023:0101-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0101-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O77AR5R2DS34JA2Y3VBBU6V4IZWVEM56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns'
  package(s) announced via the openSUSE-SU-2023:0101-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pdns-recursor fixes the following issues:

     pdns-recursor was updated to 4.6.6:

  * fixes deterred spoofing attempts can lead to authoritative servers being
       marked unavailable (boo#1209897, CVE-2023-26437)

     Fixes in 4.6.5:

  * When an expired NSEC3 entry is seen, move it to the front
       of the expiry queue

  * Log invalid RPZ content when obtained via IXFR

  * Detect invalid bytes in makeBytesFromHex()

  * Timeout handling for IXFRs as a client

     Fixes in 4.6.4:

  * Check qperq limit if throttling happened, as it increases counters

  * Failure to retrieve DNSKEYs of an Insecure zone should not be fatal

  * Resize answer length to actual received length in udpQueryResponse");

  script_tag(name:"affected", value:"'pdns' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~4.6.6~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor-debuginfo", rpm:"pdns-recursor-debuginfo~4.6.6~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor-debugsource", rpm:"pdns-recursor-debugsource~4.6.6~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~4.6.6~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor-debuginfo", rpm:"pdns-recursor-debuginfo~4.6.6~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor-debugsource", rpm:"pdns-recursor-debugsource~4.6.6~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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