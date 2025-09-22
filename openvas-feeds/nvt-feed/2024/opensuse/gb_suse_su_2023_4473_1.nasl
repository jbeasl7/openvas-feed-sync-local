# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833550");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-46752", "CVE-2023-46753");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 20:35:08 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:21:40 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for frr (SUSE-SU-2023:4473-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4473-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GXURXO2PY3IZDNRXZ75OCZLG6447ZLUK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr'
  package(s) announced via the SUSE-SU-2023:4473-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for frr fixes the following issues:

  * CVE-2023-46753: Fixed a crash caused from a crafted BGP UPDATE message.
      (bsc#1216626)

  * CVE-2023-46752: Fixed a crash caused from a mishandled malformed
      MP_REACH_NLRI data. (bsc#1216627)

  ##");

  script_tag(name:"affected", value:"'frr' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0-debuginfo", rpm:"libmlag_pb0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0", rpm:"libfrrzmq0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0", rpm:"libfrrfpm_pb0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debuginfo", rpm:"frr-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0-debuginfo", rpm:"libfrrcares0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0-debuginfo", rpm:"libfrrfpm_pb0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0", rpm:"libfrrospfapiclient0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0-debuginfo", rpm:"libfrrzmq0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0", rpm:"libfrr_pb0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0", rpm:"libmlag_pb0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debugsource", rpm:"frr-debugsource~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0-debuginfo", rpm:"libfrr_pb0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0", rpm:"libfrrsnmp0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0-debuginfo", rpm:"libfrr0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0-debuginfo", rpm:"libfrrospfapiclient0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0", rpm:"libfrrcares0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0-debuginfo", rpm:"libfrrsnmp0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-devel", rpm:"frr-devel~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0", rpm:"libfrr0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0-debuginfo", rpm:"libmlag_pb0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0", rpm:"libfrrzmq0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0", rpm:"libfrrfpm_pb0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debuginfo", rpm:"frr-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0-debuginfo", rpm:"libfrrcares0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrfpm_pb0-debuginfo", rpm:"libfrrfpm_pb0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0", rpm:"libfrrospfapiclient0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrzmq0-debuginfo", rpm:"libfrrzmq0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0", rpm:"libfrr_pb0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlag_pb0", rpm:"libmlag_pb0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-debugsource", rpm:"frr-debugsource~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr", rpm:"frr~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr_pb0-debuginfo", rpm:"libfrr_pb0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0", rpm:"libfrrsnmp0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0-debuginfo", rpm:"libfrr0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrospfapiclient0-debuginfo", rpm:"libfrrospfapiclient0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrcares0", rpm:"libfrrcares0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrrsnmp0-debuginfo", rpm:"libfrrsnmp0-debuginfo~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"frr-devel", rpm:"frr-devel~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfrr0", rpm:"libfrr0~8.4~150500.4.11.1", rls:"openSUSELeap15.5"))) {
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