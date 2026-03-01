# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0574.1");
  script_cve_id("CVE-2025-4476", "CVE-2026-0716", "CVE-2026-1761");
  script_tag(name:"creation_date", value:"2026-02-20 04:36:11 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-02 14:16:34 +0000 (Mon, 02 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0574-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260574-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024351.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup2' package(s) announced via the SUSE-SU-2026:0574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup2 fixes the following issues:

- CVE-2026-1761: incorrect length calculation when parsing of multipart HTTP responses can lead to a stack-based buffer overflow
 (bsc#1257598).
- CVE-2026-0716: improper bounds handling may allow out-of-bounds read (bsc#1256418).
- CVE-2025-4476: null pointer dereference may lead to denial of service (bsc#1243422).");

  script_tag(name:"affected", value:"'libsoup2' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1", rpm:"libsoup-2_4-1~2.74.3~150600.4.24.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2-devel", rpm:"libsoup2-devel~2.74.3~150600.4.24.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2-lang", rpm:"libsoup2-lang~2.74.3~150600.4.24.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-2_4", rpm:"typelib-1_0-Soup-2_4~2.74.3~150600.4.24.1", rls:"SLES15.0SP6"))) {
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
