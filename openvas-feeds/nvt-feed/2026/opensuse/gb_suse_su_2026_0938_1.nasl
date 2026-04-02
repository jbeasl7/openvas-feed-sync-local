# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0938.1");
  script_cve_id("CVE-2026-28691", "CVE-2026-30883");
  script_tag(name:"creation_date", value:"2026-03-23 04:46:34 +0000 (Mon, 23 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-13 17:10:28 +0000 (Fri, 13 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0938-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260938-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259467");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024784.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick' package(s) announced via the SUSE-SU-2026:0938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for GraphicsMagick fixes the following issues:

- CVE-2026-28691: missing check in the JBIG decoder can lead to an uninitialized pointer dereference (bsc#1259455).
- CVE-2026-30883: missing bounds check when encoding a PNG image can lead to a heap buffer over-write (bsc#1259467).");

  script_tag(name:"affected", value:"'GraphicsMagick' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12", rpm:"libGraphicsMagick++-Q16-12~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.42~150600.3.15.1", rls:"openSUSELeap15.6"))) {
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
