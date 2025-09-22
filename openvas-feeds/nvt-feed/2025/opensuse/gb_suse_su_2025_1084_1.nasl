# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1084.1");
  script_cve_id("CVE-2025-30472");
  script_tag(name:"creation_date", value:"2025-04-03 04:06:03 +0000 (Thu, 03 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-01 20:28:02 +0000 (Tue, 01 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1084-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251084-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239987");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038870.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'corosync' package(s) announced via the SUSE-SU-2025:1084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for corosync fixes the following issues:

- CVE-2025-30472: Fixed stack buffer overflow from 'orf_token_endian_convert' (bsc#1239987)");

  script_tag(name:"affected", value:"'corosync' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"corosync", rpm:"corosync~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corosync-qdevice", rpm:"corosync-qdevice~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corosync-qnetd", rpm:"corosync-qnetd~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corosync-testagents", rpm:"corosync-testagents~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcfg6", rpm:"libcfg6~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcfg6-32bit", rpm:"libcfg6-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcmap4", rpm:"libcmap4~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcmap4-32bit", rpm:"libcmap4-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcorosync-devel", rpm:"libcorosync-devel~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcorosync_common4", rpm:"libcorosync_common4~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcorosync_common4-32bit", rpm:"libcorosync_common4-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcpg4", rpm:"libcpg4~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcpg4-32bit", rpm:"libcpg4-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquorum5", rpm:"libquorum5~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquorum5-32bit", rpm:"libquorum5-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsam4", rpm:"libsam4~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsam4-32bit", rpm:"libsam4-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtotem_pg5", rpm:"libtotem_pg5~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtotem_pg5-32bit", rpm:"libtotem_pg5-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvotequorum8", rpm:"libvotequorum8~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvotequorum8-32bit", rpm:"libvotequorum8-32bit~2.4.6~150300.12.13.1", rls:"openSUSELeap15.6"))) {
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
