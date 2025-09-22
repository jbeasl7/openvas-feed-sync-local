# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0601.1");
  script_cve_id("CVE-2024-45337", "CVE-2025-21613");
  script_tag(name:"creation_date", value:"2025-02-24 04:07:13 +0000 (Mon, 24 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0601-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0601-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250601-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235573");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020385.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'brise' package(s) announced via the SUSE-SU-2025:0601-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for brise fixes the following issues:

- CVE-2025-21613: Fixed argument injection via the URL field (bsc#1235573).
- CVE-2024-45337: Fixed authorization bypass in golang.org/x/crypto via the ServerConfig.PublicKeyCallback callback
 (bsc#1234597).");

  script_tag(name:"affected", value:"'brise' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-all", rpm:"rime-schema-all~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-array", rpm:"rime-schema-array~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-bopomofo", rpm:"rime-schema-bopomofo~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-cangjie", rpm:"rime-schema-cangjie~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-cantonese", rpm:"rime-schema-cantonese~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-combo-pinyin", rpm:"rime-schema-combo-pinyin~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-custom", rpm:"rime-schema-custom~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-default", rpm:"rime-schema-default~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-double-pinyin", rpm:"rime-schema-double-pinyin~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-emoji", rpm:"rime-schema-emoji~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-essay", rpm:"rime-schema-essay~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-essay-simp", rpm:"rime-schema-essay-simp~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-extra", rpm:"rime-schema-extra~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-ipa", rpm:"rime-schema-ipa~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-luna-pinyin", rpm:"rime-schema-luna-pinyin~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-middle-chinese", rpm:"rime-schema-middle-chinese~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-pinyin-simp", rpm:"rime-schema-pinyin-simp~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-prelude", rpm:"rime-schema-prelude~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-quick", rpm:"rime-schema-quick~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-scj", rpm:"rime-schema-scj~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-soutzoe", rpm:"rime-schema-soutzoe~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-stenotype", rpm:"rime-schema-stenotype~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-stroke", rpm:"rime-schema-stroke~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-terra-pinyin", rpm:"rime-schema-terra-pinyin~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-wubi", rpm:"rime-schema-wubi~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rime-schema-wugniu", rpm:"rime-schema-wugniu~20230603+git.5fdd2d6~150600.3.8.1", rls:"openSUSELeap15.6"))) {
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
