# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.979101710063100997");
  script_cve_id("CVE-2025-29915", "CVE-2025-29916", "CVE-2025-29917", "CVE-2025-29918");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-30T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-05-30 05:40:08 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-29 15:47:22 +0000 (Thu, 29 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-a9e7d63dc7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a9e7d63dc7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a9e7d63dc7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'suricata' package(s) announced via the FEDORA-2025-a9e7d63dc7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is an extra release to address a critical issue in 7.0.9 affecting AF_PACKET users: setting a BPF would cause Suricata to fail to start up. This has been fixed.

----

Various security, performance, accuracy, and stability issues have been fixed. LibHTP has been updated to version 0.5.50 which is bundled with this new release. This fixes:

CVE-2025-29915: HIGH
CVE-2025-29917: HIGH
CVE-2025-29918: HIGH
CVE-2025-29916: Moderate");

  script_tag(name:"affected", value:"'suricata' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"suricata", rpm:"suricata~7.0.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suricata-debuginfo", rpm:"suricata-debuginfo~7.0.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suricata-debugsource", rpm:"suricata-debugsource~7.0.10~1.fc42", rls:"FC42"))) {
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
