# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0290.1");
  script_cve_id("CVE-2023-1668", "CVE-2023-3152", "CVE-2023-3153", "CVE-2023-3966", "CVE-2023-5366", "CVE-2024-2182", "CVE-2025-0650");
  script_tag(name:"creation_date", value:"2026-01-28 04:21:39 +0000 (Wed, 28 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-07 18:15:10 +0000 (Wed, 07 Jun 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0290-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0290-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260290-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255435");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023918.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch3' package(s) announced via the SUSE-SU-2026:0290-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch3 fixes the following issues:

Update to v3.1.7:

 - CVE-2023-3966: openvswitch, openvswitch3: Invalid memory access in Geneve with HW offload (bsc#1219465).
 - CVE-2024-2182: openvswitch: ov: insufficient validation of incoming BFD packets may lead to denial of service (bsc#1255435).
 - CVE-2023-1668: openvswitch: remote traffic denial of service via crafted packets with IP proto 0 (bsc#1210054).
 - CVE-2023-3153: openvswitch,openvswitch3: service monitor MAC flow is not rate limited (bsc#1212125).
 - CVE-2023-5366: openvswitch: missing masks on a final stage with ports trie (bsc#1216002).");

  script_tag(name:"affected", value:"'openvswitch3' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3", rpm:"openvswitch3~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-devel", rpm:"openvswitch3-devel~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-doc", rpm:"openvswitch3-doc~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-ipsec", rpm:"openvswitch3-ipsec~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-pki", rpm:"openvswitch3-pki~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-test", rpm:"openvswitch3-test~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-vtep", rpm:"openvswitch3-vtep~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3", rpm:"ovn3~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-central", rpm:"ovn3-central~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-devel", rpm:"ovn3-devel~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-doc", rpm:"ovn3-doc~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-docker", rpm:"ovn3-docker~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-host", rpm:"ovn3-host~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-vtep", rpm:"ovn3-vtep~23.03.3~150500.3.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ovs3", rpm:"python3-ovs3~3.1.7~150500.3.25.1", rls:"openSUSELeap15.6"))) {
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
