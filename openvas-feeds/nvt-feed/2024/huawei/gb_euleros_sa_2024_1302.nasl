# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1302");
  script_cve_id("CVE-2023-3899");
  script_tag(name:"creation_date", value:"2024-03-12 04:24:08 +0000 (Tue, 12 Mar 2024)");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-30 17:19:04 +0000 (Wed, 30 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for subscription-manager (EulerOS-SA-2024-1302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1302");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1302");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'subscription-manager' package(s) announced via the EulerOS-SA-2024-1302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in subscription-manager that allows local privilege escalation due to inadequate authorization. The D-Bus interface com.redhat.RHSM1 exposes a significant number of methods to all users that could change the state of the registration. By using the com.redhat.RHSM1.Config.SetAll() method, a low-privileged local user could tamper with the state of the registration, by unregistering the system or by changing the current entitlements. This flaw allows an attacker to set arbitrary configuration directives for /etc/rhsm/rhsm.conf, which can be abused to cause a local privilege escalation to an unconfined root.(CVE-2023-3899)");

  script_tag(name:"affected", value:"'subscription-manager' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"dnf-plugin-subscription-manager", rpm:"dnf-plugin-subscription-manager~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-subscription-manager-rhsm", rpm:"python2-subscription-manager-rhsm~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-subscription-manager-rhsm", rpm:"python3-subscription-manager-rhsm~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-syspurpose", rpm:"python3-syspurpose~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subscription-manager", rpm:"subscription-manager~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subscription-manager-cockpit", rpm:"subscription-manager-cockpit~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subscription-manager-plugin-container", rpm:"subscription-manager-plugin-container~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subscription-manager-plugin-ostree", rpm:"subscription-manager-plugin-ostree~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subscription-manager-rhsm-certificates", rpm:"subscription-manager-rhsm-certificates~1.23.3~1.h3.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
