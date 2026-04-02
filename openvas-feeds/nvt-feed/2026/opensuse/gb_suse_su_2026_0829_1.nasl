# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0829.1");
  script_cve_id("CVE-2025-14831");
  script_tag(name:"creation_date", value:"2026-03-09 04:37:52 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-09 15:16:09 +0000 (Mon, 09 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0829-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0829-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260829-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258083");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024630.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2026:0829-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnutls fixes the following issues:

Security issue:

- CVE-2025-14831: excessive resource consumption when verifying specially crafted malicious certificates containing a
 large number of name constraints and subject alternative names (bsc#1257960).

Other updates and bugfixes:

- update libgnutls package to avoid binder getting calculated with SHA256 (bsc#1258083, jsc#PED-15752, jsc#PED-15753).
- lib/psk: Add gnutls_psk_allocate_{client,server}_credentials2
- tests/psk-file: Add testing for _credentials2 functions
- lib/psk: add null check for binder algo
- pre_shared_key: fix memleak when retrying with different binder algo
- pre_shared_key: add null check on pskcred");

  script_tag(name:"affected", value:"'gnutls' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel-32bit", rpm:"libgnutls-devel-32bit~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx30", rpm:"libgnutlsxx30~3.8.3~150600.4.17.1", rls:"openSUSELeap15.6"))) {
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
