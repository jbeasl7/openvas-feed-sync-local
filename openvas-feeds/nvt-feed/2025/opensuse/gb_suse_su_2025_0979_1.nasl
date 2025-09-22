# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0979.1");
  script_cve_id("CVE-2025-2173", "CVE-2025-2174", "CVE-2025-2175", "CVE-2025-2176", "CVE-2025-2177");
  script_tag(name:"creation_date", value:"2025-03-24 04:06:35 +0000 (Mon, 24 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-11 08:15:12 +0000 (Tue, 11 Mar 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0979-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0979-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250979-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239320");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020575.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zvbi' package(s) announced via the SUSE-SU-2025:0979-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zvbi fixes the following issues:

 - CVE-2025-2173: Fixed check on src_length to avoid an unitinialized heap read (bsc#1239222).
 - CVE-2025-2174: Fixed integer overflow leading to heap overflow in src/conv.c, src/io-sim.c, src/search.c (bsc#1239299).
 - CVE-2025-2175: Fixed integer overflow in _vbi_strndup_iconv (bsc#1239312).
 - CVE-2025-2176: Fixed integer overflow in function vbi_capture_sim_load_caption in src/io-sim.c (bsc#1239319).
 - CVE-2025-2177: Fixed integer overflow in function vbi_search_new in src/search.c (bsc#1239320).");

  script_tag(name:"affected", value:"'zvbi' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzvbi-chains0", rpm:"libzvbi-chains0~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzvbi-chains0-32bit", rpm:"libzvbi-chains0-32bit~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzvbi0", rpm:"libzvbi0~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzvbi0-32bit", rpm:"libzvbi0-32bit~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zvbi", rpm:"zvbi~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zvbi-devel", rpm:"zvbi-devel~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zvbi-devel-32bit", rpm:"zvbi-devel-32bit~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zvbi-lang", rpm:"zvbi-lang~0.2.35~150000.4.3.1", rls:"openSUSELeap15.6"))) {
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
