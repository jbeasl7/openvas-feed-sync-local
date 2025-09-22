# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2195.2");
  script_cve_id("CVE-2015-4491", "CVE-2015-7673", "CVE-2015-7674");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2195-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2195-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152195-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948791");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001761.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf' package(s) announced via the SUSE-SU-2015:2195-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The gdk pixbuf library was updated to fix three security issues.

These security issues were fixed:
- CVE-2015-7673: Fix some more overflows scaling a gif (bsc#948791)
- CVE-2015-4491: Check for overflow before allocating memory when scaling (bsc#942801)
- CVE-2015-7673: Fix an overflow and DoS when scaling TGA files (bsc#948790).
- CVE-2015-7674: Fix overflow when scaling GIF files(bsc#948791).");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.30.6~7.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.30.6~7.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.30.6~7.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.30.6~7.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.30.6~7.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.30.6~7.2", rls:"SLES12.0SP1"))) {
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
