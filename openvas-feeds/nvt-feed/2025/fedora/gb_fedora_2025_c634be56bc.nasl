# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9963498101569899");
  script_cve_id("CVE-2024-38311", "CVE-2024-56195", "CVE-2024-56202");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-c634be56bc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c634be56bc");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c634be56bc");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350625");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350627");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350629");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trafficserver' package(s) announced via the FEDORA-2025-c634be56bc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Changes with Apache Traffic Server 9.2.9
 #12071 - Fix chunked pipelined requests
 #12075 - Fix send 100 Continue optimization for GET
 #12077 - Fix intercept plugin ignoring ACL
 #12079 - ACL combination tests for 9.2.x");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"trafficserver", rpm:"trafficserver~9.2.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-debuginfo", rpm:"trafficserver-debuginfo~9.2.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-debugsource", rpm:"trafficserver-debugsource~9.2.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-devel", rpm:"trafficserver-devel~9.2.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-perl", rpm:"trafficserver-perl~9.2.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trafficserver-selinux", rpm:"trafficserver-selinux~9.2.9~1.fc41", rls:"FC41"))) {
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
