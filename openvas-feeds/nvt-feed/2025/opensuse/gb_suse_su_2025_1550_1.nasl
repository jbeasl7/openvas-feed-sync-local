# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1550.1");
  script_cve_id("CVE-2025-27587");
  script_tag(name:"creation_date", value:"2025-05-16 09:44:49 +0000 (Fri, 16 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1550-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1550-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251550-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240607");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039218.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-3' package(s) announced via the SUSE-SU-2025:1550-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3 fixes the following issues:

Security:

- CVE-2025-27587: Timing side channel vulnerability in the P-384
 implementation when used with ECDSA in the PPC architecture (bsc#1240366).
- Missing null pointer check before accessing handshake_func in ssl_lib.c (bsc#1240607).

FIPS:

- Disabling EMS in OpenSSL configuration prevents sshd from starting (bsc#1230959, bsc#1232326, bsc#1231748).");

  script_tag(name:"affected", value:"'openssl-3' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel-32bit", rpm:"libopenssl-3-devel-32bit~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-fips-provider", rpm:"libopenssl-3-fips-provider~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-fips-provider-32bit", rpm:"libopenssl-3-fips-provider-32bit~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-32bit", rpm:"libopenssl3-32bit~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-doc", rpm:"openssl-3-doc~3.1.4~150600.5.27.1", rls:"openSUSELeap15.6"))) {
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
