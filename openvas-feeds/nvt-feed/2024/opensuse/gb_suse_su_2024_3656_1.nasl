# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856600");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2018-16886", "CVE-2020-15106", "CVE-2020-15112", "CVE-2021-28235", "CVE-2022-41723", "CVE-2023-29406", "CVE-2023-47108", "CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-10-17 04:03:19 +0000 (Thu, 17 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-10 18:55:24 +0000 (Mon, 10 Apr 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3656-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3656-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243656-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218150");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/compare/v3.3.1...v3.5.12");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037265.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'etcd' package(s) announced via the SUSE-SU-2024:3656-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2018-16873: Fixed remote command execution in cmd/go (bsc#1118897)
- CVE-2018-16874: Fixed directory traversal in cmd/go (bsc#1118898)
- CVE-2018-16875: Fixed CPU denial of service in crypto/x509 (bsc#1118899)
- CVE-2018-16886: Fixed improper authentication issue when RBAC and client-cert-auth is enabled (bsc#1121850)
- CVE-2020-15106: Fixed panic in decodeRecord method (bsc#1174951)
- CVE-2020-15112: Fixed improper checks in entry index (bsc#1174951)
- CVE-2021-28235: Fixed information discosure via debug function (bsc#1210138)
- CVE-2022-41723: Fixed quadratic complexity in HPACK decoding in net/http (bsc#1208270, bsc#1208297)
- CVE-2023-29406: Fixed insufficient sanitization of Host header in go net/http (bsc#1213229)
- CVE-2023-47108: Fixed DoS vulnerability in otelgrpc (bsc#1217070)
- CVE-2023-48795: Fixed prefix truncation breaking ssh channel integrity (aka Terrapin Attack) in crypto/ssh (bsc#1217950, bsc#1218150)

Other changes:

- Added hardening to systemd service(s) (bsc#1181400)
- Fixed static /tmp file issue (bsc#1199031)
- Fixed systemd service not starting (bsc#1183703)

Full changelog:

[link moved to references]");

  script_tag(name:"affected", value:"'etcd' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"etcd", rpm:"etcd~3.5.12~150000.7.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcdctl", rpm:"etcdctl~3.5.12~150000.7.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"etcd", rpm:"etcd~3.5.12~150000.7.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcdctl", rpm:"etcdctl~3.5.12~150000.7.6.1", rls:"openSUSELeap15.6"))) {
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
