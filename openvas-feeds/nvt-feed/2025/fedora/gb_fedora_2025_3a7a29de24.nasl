# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3977972910010124");
  script_cve_id("CVE-2025-27830", "CVE-2025-27831", "CVE-2025-27832", "CVE-2025-27833", "CVE-2025-27834", "CVE-2025-27835", "CVE-2025-27836", "CVE-2025-27837");
  script_tag(name:"creation_date", value:"2025-04-10 04:04:51 +0000 (Thu, 10 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-3a7a29de24)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3a7a29de24");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3a7a29de24");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354947");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354948");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354949");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354952");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354953");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354954");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354961");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354963");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355007");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355009");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355011");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355015");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355019");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355021");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355023");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2355025");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the FEDORA-2025-3a7a29de24 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-27835 ghostscript: Buffer overflow when converting glyphs to unicode (fedora#2355025)

CVE-2025-27834 ghostscript: Buffer overflow caused by an oversized Type 4 function in a PDF (fedora#2355023)

CVE-2025-27832 ghostscript: NPDL device: Compression buffer overflow (fedora#2355021)

CVE-2025-27836 ghostscript: device: Print buffer overflow (fedora#2355019)

CVE-2025-27830 ghostscript: Buffer overflow during serialization of DollarBlend in font (fedora#2355015)

CVE-2025-27833 ghostscript: Buffer overflow with long TTF font name (fedora#2355011)

CVE-2025-27837 ghostscript: Access to arbitrary files through truncated path with invalid UTF-8 (fedora#2355009)

CVE-2025-27831 ghostscript: Text buffer overflow with long characters (fedora#2355007)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk-debuginfo", rpm:"ghostscript-gtk-debuginfo~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-dvipdf", rpm:"ghostscript-tools-dvipdf~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-fonts", rpm:"ghostscript-tools-fonts~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-printing", rpm:"ghostscript-tools-printing~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs", rpm:"libgs~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-debuginfo", rpm:"libgs-debuginfo~10.02.1~14.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~10.02.1~14.fc40", rls:"FC40"))) {
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
