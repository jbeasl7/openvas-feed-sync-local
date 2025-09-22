# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2934");
  script_cve_id("CVE-2024-45310");
  script_tag(name:"creation_date", value:"2024-12-12 04:32:26 +0000 (Thu, 12 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for docker-runc (EulerOS-SA-2024-2934)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2934");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2934");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'docker-runc' package(s) announced via the EulerOS-SA-2024-2934 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"runc is a CLI tool for spawning and running containers according to the OCI specification. runc 1.1.13 and earlier, as well as 1.2.0-rc2 and earlier, can be tricked into creating empty files or directories in arbitrary locations in the host filesystem by sharing a volume between two containers and exploiting a race with `os.MkdirAll`. While this could be used to create empty files, existing files would not be truncated. An attacker must have the ability to start containers using some kind of custom volume configuration. Containers using user namespaces are still affected, but the scope of places an attacker can create inodes can be significantly reduced. Sufficiently strict LSM policies (SELinux/Apparmor) can also in principle block this attack -- we suspect the industry standard SELinux policy may restrict this attack's scope but the exact scope of protection hasn't been analysed. This is exploitable using runc directly as well as through Docker and Kubernetes. The issue is fixed in runc v1.1.14 and v1.2.0-rc3. Some workarounds are available. Using user namespaces restricts this attack fairly significantly such that the attacker can only create inodes in directories that the remapped root user/group has write access to. Unless the root user is remapped to an actual user on the host (such as with rootless containers that don't use `/etc/sub[ug]id`), this in practice means that an attacker would only be able to create inodes in world-writable directories. A strict enough SELinux or AppArmor policy could in principle also restrict the scope if a specific label is applied to the runc runtime, though neither the extent to which the standard existing policies block this attack nor what exact policies are needed to sufficiently restrict this attack have been thoroughly tested.(CVE-2024-45310)");

  script_tag(name:"affected", value:"'docker-runc' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.1.3~9.h29.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
