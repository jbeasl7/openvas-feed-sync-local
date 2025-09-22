# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2660.1");
  script_cve_id("CVE-2024-6655");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 15:15:12 +0000 (Tue, 16 Jul 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2660-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2660-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242660-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228120");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036188.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk2' package(s) announced via the SUSE-SU-2024:2660-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gtk2 fixes the following issues:

- CVE-2024-6655: Fixed library injection from current working directory (bsc#1228120)");

  script_tag(name:"affected", value:"'gtk2' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"gtk2-branding-upstream", rpm:"gtk2-branding-upstream~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-data", rpm:"gtk2-data~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-devel", rpm:"gtk2-devel~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-devel-32bit", rpm:"gtk2-devel-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-amharic", rpm:"gtk2-immodule-amharic~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-amharic-32bit", rpm:"gtk2-immodule-amharic-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-inuktitut", rpm:"gtk2-immodule-inuktitut~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-inuktitut-32bit", rpm:"gtk2-immodule-inuktitut-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-multipress", rpm:"gtk2-immodule-multipress~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-multipress-32bit", rpm:"gtk2-immodule-multipress-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-thai", rpm:"gtk2-immodule-thai~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-thai-32bit", rpm:"gtk2-immodule-thai-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-tigrigna", rpm:"gtk2-immodule-tigrigna~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-tigrigna-32bit", rpm:"gtk2-immodule-tigrigna-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-vietnamese", rpm:"gtk2-immodule-vietnamese~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-vietnamese-32bit", rpm:"gtk2-immodule-vietnamese-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-xim", rpm:"gtk2-immodule-xim~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-immodule-xim-32bit", rpm:"gtk2-immodule-xim-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-lang", rpm:"gtk2-lang~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-tools", rpm:"gtk2-tools~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-tools-32bit", rpm:"gtk2-tools-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-2_0-0", rpm:"libgtk-2_0-0~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-2_0-0-32bit", rpm:"libgtk-2_0-0-32bit~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Gtk-2_0", rpm:"typelib-1_0-Gtk-2_0~2.24.33~150400.4.3.1", rls:"openSUSELeap15.5"))) {
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
