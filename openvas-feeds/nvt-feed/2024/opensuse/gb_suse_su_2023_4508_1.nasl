# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833351");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-5366");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 17:40:07 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:46:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for openvswitch (SUSE-SU-2023:4508-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4508-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QLG7LQY5U5I3LBJNONRLHZV54TAUSCFS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch'
  package(s) announced via the SUSE-SU-2023:4508-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch fixes the following issues:

  * CVE-2023-5366: Fixed missing masks on a final stage with ports trie
      (bsc#1216002).

  ##");

  script_tag(name:"affected", value:"'openvswitch' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-2_14-0", rpm:"libopenvswitch-2_14-0~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-debugsource", rpm:"openvswitch-debugsource~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-2_14-0-debuginfo", rpm:"libopenvswitch-2_14-0-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-test-debuginfo", rpm:"openvswitch-test-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-debuginfo", rpm:"openvswitch-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn", rpm:"ovn~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-vtep-debuginfo", rpm:"openvswitch-vtep-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-host", rpm:"ovn-host~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ovs", rpm:"python3-ovs~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-vtep", rpm:"openvswitch-vtep~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-20_06-0-debuginfo", rpm:"libovn-20_06-0-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-central-debuginfo", rpm:"ovn-central-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch", rpm:"openvswitch~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-test", rpm:"openvswitch-test~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-devel", rpm:"openvswitch-devel~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-host-debuginfo", rpm:"ovn-host-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-central", rpm:"ovn-central~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-20_06-0", rpm:"libovn-20_06-0~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-pki", rpm:"openvswitch-pki~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-vtep", rpm:"ovn-vtep~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-docker", rpm:"ovn-docker~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-ipsec", rpm:"openvswitch-ipsec~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-devel", rpm:"ovn-devel~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-debuginfo", rpm:"ovn-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-vtep-debuginfo", rpm:"ovn-vtep-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-doc", rpm:"openvswitch-doc~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-doc", rpm:"ovn-doc~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-2_14-0", rpm:"libopenvswitch-2_14-0~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-debugsource", rpm:"openvswitch-debugsource~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenvswitch-2_14-0-debuginfo", rpm:"libopenvswitch-2_14-0-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-test-debuginfo", rpm:"openvswitch-test-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-debuginfo", rpm:"openvswitch-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn", rpm:"ovn~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-vtep-debuginfo", rpm:"openvswitch-vtep-debuginfo~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-host", rpm:"ovn-host~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ovs", rpm:"python3-ovs~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-vtep", rpm:"openvswitch-vtep~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-20_06-0-debuginfo", rpm:"libovn-20_06-0-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-central-debuginfo", rpm:"ovn-central-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch", rpm:"openvswitch~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-test", rpm:"openvswitch-test~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-devel", rpm:"openvswitch-devel~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-host-debuginfo", rpm:"ovn-host-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-central", rpm:"ovn-central~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libovn-20_06-0", rpm:"libovn-20_06-0~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-pki", rpm:"openvswitch-pki~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-vtep", rpm:"ovn-vtep~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-docker", rpm:"ovn-docker~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-ipsec", rpm:"openvswitch-ipsec~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-devel", rpm:"ovn-devel~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-debuginfo", rpm:"ovn-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-vtep-debuginfo", rpm:"ovn-vtep-debuginfo~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-doc", rpm:"openvswitch-doc~2.14.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovn-doc", rpm:"ovn-doc~20.06.2~150300.19.11.1", rls:"openSUSELeap15.3"))) {
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
