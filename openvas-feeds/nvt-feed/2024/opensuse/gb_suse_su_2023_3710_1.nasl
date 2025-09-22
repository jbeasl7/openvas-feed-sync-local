# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833481");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-3152", "CVE-2023-3153");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-13 21:26:54 +0000 (Tue, 13 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:26:20 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for openvswitch3 (SUSE-SU-2023:3710-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3710-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OO5B25TZTDDYSLYM2BYQKLHD5QTY7ERL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch3'
  package(s) announced via the SUSE-SU-2023:3710-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch3 fixes the following issues:

  * CVE-2023-3153: Fixed service monitor MAC flow is not rate limited
      (bsc#1212125).

  ##");

  script_tag(name:"affected", value:"'openvswitch3' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ovn3-debuginfo", rpm:"ovn3-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-test", rpm:"openvswitch3-test~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-host", rpm:"ovn3-host~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-23_03-0-debuginfo", rpm:"libovn-23_03-0-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-debugsource", rpm:"openvswitch3-debugsource~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-3_1-0", rpm:"libopenvswitch-3_1-0~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-vtep", rpm:"openvswitch3-vtep~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-ipsec", rpm:"openvswitch3-ipsec~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3", rpm:"ovn3~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-devel", rpm:"openvswitch3-devel~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-devel", rpm:"ovn3-devel~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-host-debuginfo", rpm:"ovn3-host-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-vtep-debuginfo", rpm:"openvswitch3-vtep-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-central-debuginfo", rpm:"ovn3-central-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3", rpm:"openvswitch3~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-vtep", rpm:"ovn3-vtep~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-debuginfo", rpm:"openvswitch3-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-central", rpm:"ovn3-central~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-3_1-0-debuginfo", rpm:"libopenvswitch-3_1-0-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-test-debuginfo", rpm:"openvswitch3-test-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ovs3", rpm:"python3-ovs3~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-23_03-0", rpm:"libovn-23_03-0~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-vtep-debuginfo", rpm:"ovn3-vtep-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-docker", rpm:"ovn3-docker~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-pki", rpm:"openvswitch3-pki~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-doc", rpm:"openvswitch3-doc~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-doc", rpm:"ovn3-doc~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-debuginfo", rpm:"ovn3-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-test", rpm:"openvswitch3-test~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-host", rpm:"ovn3-host~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-23_03-0-debuginfo", rpm:"libovn-23_03-0-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-debugsource", rpm:"openvswitch3-debugsource~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-3_1-0", rpm:"libopenvswitch-3_1-0~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-vtep", rpm:"openvswitch3-vtep~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-ipsec", rpm:"openvswitch3-ipsec~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3", rpm:"ovn3~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-devel", rpm:"openvswitch3-devel~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-devel", rpm:"ovn3-devel~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-host-debuginfo", rpm:"ovn3-host-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-vtep-debuginfo", rpm:"openvswitch3-vtep-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-central-debuginfo", rpm:"ovn3-central-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3", rpm:"openvswitch3~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-vtep", rpm:"ovn3-vtep~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-debuginfo", rpm:"openvswitch3-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-central", rpm:"ovn3-central~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-3_1-0-debuginfo", rpm:"libopenvswitch-3_1-0-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-test-debuginfo", rpm:"openvswitch3-test-debuginfo~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ovs3", rpm:"python3-ovs3~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-23_03-0", rpm:"libovn-23_03-0~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-vtep-debuginfo", rpm:"ovn3-vtep-debuginfo~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-docker", rpm:"ovn3-docker~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-pki", rpm:"openvswitch3-pki~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch3-doc", rpm:"openvswitch3-doc~3.1.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn3-doc", rpm:"ovn3-doc~23.03.0~150500.3.6.2", rls:"openSUSELeap15.5"))) {
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