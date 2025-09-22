# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123510");
  script_cve_id("CVE-2013-0343", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-4345", "CVE-2013-4387", "CVE-2013-4592");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:50 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-2583)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2583");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2583.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-16.2.2.el6uek, kernel-uek' package(s) announced via the ELSA-2013-2583 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.8.13-16.2.2.el6uek]
- HID: pantherlord: validate output report details (Kees Cook) [Orabug: 17841973] {CVE-2013-2892}
- HID: zeroplus: validate output report details (Kees Cook) [Orabug: 17841968] {CVE-2013-2889}
- HID: provide a helper for validating hid reports (Kees Cook) [Orabug: 17841968] {CVE-2013-2889}
- KVM: Fix iommu map/unmap to handle memory slot moves (Alex Williamson) [Orabug: 17841960] {CVE-2013-4592}
- ansi_cprng: Fix off by one error in non-block size request (Jerry Snitselaar) [Orabug: 17837997] {CVE-2013-4345}
- HID: validate HID report id size (Kees Cook) [Orabug: 17841940] {CVE-2013-2888}
- ipv6: remove max_addresses check from ipv6_create_tempaddr (Hannes Frederic Sowa) [Orabug: 17841911] {CVE-2013-0343}
- ipv6: udp packets following an UFO enqueued packet need also be handled by UFO (Hannes Frederic Sowa) [Orabug: 17841928] {CVE-2013-4387}");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-16.2.2.el6uek, kernel-uek' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-16.2.2.el6uek", rpm:"dtrace-modules-3.8.13-16.2.2.el6uek~0.4.1~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-16.2.2.el6uek-headers", rpm:"dtrace-modules-3.8.13-16.2.2.el6uek-headers~0.4.1~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-16.2.2.el6uek-provider-headers", rpm:"dtrace-modules-3.8.13-16.2.2.el6uek-provider-headers~0.4.1~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~3.8.13~16.2.2.el6uek", rls:"OracleLinux6"))) {
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
