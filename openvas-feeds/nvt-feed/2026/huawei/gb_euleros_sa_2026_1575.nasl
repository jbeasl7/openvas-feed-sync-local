# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1575");
  script_cve_id("CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881");
  script_tag(name:"creation_date", value:"2026-03-17 04:55:49 +0000 (Tue, 17 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-03 18:30:15 +0000 (Wed, 03 Dec 2025)");

  script_name("Huawei EulerOS: Security Advisory for docker-runc (EulerOS-SA-2026-1575)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1575");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1575");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-runc' package(s) announced via the EulerOS-SA-2026-1575 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"runc is a CLI tool for spawning and running containers according to the OCI specification. Versions 1.0.0-rc3 through 1.2.7, 1.3.0-rc.1 through 1.3.2, and 1.4.0-rc.1 through 1.4.0-rc.2, due to insufficient checks when bind-mounting `/dev/pts/$n` to `/dev/console` inside the container, an attacker can trick runc into bind-mounting paths which would normally be made read-only or be masked onto a path that the attacker can write to. This attack is very similar in concept and application to CVE-2025-31133, except that it attacks a similar vulnerability in a different target (namely, the bind-mount of `/dev/pts/$n` to `/dev/console` as configured for all containers that allocate a console). This happens after `pivot_root(2)`, so this cannot be used to write to host files directly -- however, as with CVE-2025-31133, this can load to denial of service of the host or a container breakout by providing the attacker with a writable copy of `/proc/sysrq-trigger` or `/proc/sys/kernel/core_pattern` (respectively). This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.(CVE-2025-52565)

runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack: an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.(CVE-2025-31133)

runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7, 1.3.2 and 1.4.0-rc.2, an attacker can trick runc into misdirecting writes to /proc to other procfs files through the use of a racing container with shared mounts (we have also verified this attack is possible to exploit using a standard Dockerfile with docker buildx build as that also permits triggering parallel execution of containers with custom shared mounts configured). This redirect could be through symbolic links in a tmpfs or theoretically other methods such as regular bind-mounts. While similar, the mitigation applied for the related CVE, CVE-2019-19921, was fairly limited and effectively only caused runc to verify that when LSM labels are written they are actually procfs files. This issue is fixed in versions 1.2.8, 1.3.3, and 1.4.0-rc.3.(CVE-2025-52881)");

  script_tag(name:"affected", value:"'docker-runc' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0.rc3~300.h32.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
