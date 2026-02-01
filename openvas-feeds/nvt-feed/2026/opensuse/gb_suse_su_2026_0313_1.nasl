# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0313.1");
  script_cve_id("CVE-2025-14422", "CVE-2025-14425");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:01 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0313-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0313-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260313-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255296");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023932.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the SUSE-SU-2026:0313-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gimp fixes the following issues:

- CVE-2025-14422: Fixed RCE vulnerability due to PNM file parsing integer overflow (bsc#1255293)
- CVE-2025-14425: Fixed RCE vulnerability due to JP2 file parsing heap-based buffer overflow (bsc#1255296)");

  script_tag(name:"affected", value:"'gimp' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-lang", rpm:"gimp-lang~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugin-aa", rpm:"gimp-plugin-aa~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0", rpm:"libgimp-2_0-0~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-32bit", rpm:"libgimp-2_0-0-32bit~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0", rpm:"libgimpui-2_0-0~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-32bit", rpm:"libgimpui-2_0-0-32bit~2.10.30~150400.3.38.1", rls:"openSUSELeap15.6"))) {
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
