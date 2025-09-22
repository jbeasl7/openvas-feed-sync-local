# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0052");
  script_cve_id("CVE-2024-11079", "CVE-2024-8775", "CVE-2024-9902");
  script_tag(name:"creation_date", value:"2025-02-13 04:08:38 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-06 10:15:06 +0000 (Wed, 06 Nov 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0052");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0052.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33828");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/2Y6RFLPB54N7XR7AP7A2DEXGLBEDEQJU/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-ansible-core' package(s) announced via the MGASA-2025-0052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Exposure of sensitive information in Ansible vault files due to improper
logging. (CVE-2024-8775)
Ansible-core user may read/write unauthorized content. (CVE-2024-9902)
Unsafe tagging bypass via hostvars object in ansible-core.
(CVE-2024-11079)");

  script_tag(name:"affected", value:"'python-ansible-core' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"python-ansible-core", rpm:"python-ansible-core~2.14.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ansible-core", rpm:"python3-ansible-core~2.14.18~1.mga9", rls:"MAGEIA9"))) {
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
