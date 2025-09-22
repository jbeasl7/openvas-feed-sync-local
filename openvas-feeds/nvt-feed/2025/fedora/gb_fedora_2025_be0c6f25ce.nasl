# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9810109961022599101");
  script_cve_id("CVE-2025-31492");
  script_tag(name:"creation_date", value:"2025-08-28 04:04:48 +0000 (Thu, 28 Aug 2025)");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-be0c6f25ce)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-be0c6f25ce");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-be0c6f25ce");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357849");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_auth_openidc' package(s) announced via the FEDORA-2025-be0c6f25ce advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebase to new version resolves CVE-2025-31492");

  script_tag(name:"affected", value:"'mod_auth_openidc' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_openidc", rpm:"mod_auth_openidc~2.4.17.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_openidc-debuginfo", rpm:"mod_auth_openidc-debuginfo~2.4.17.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_openidc-debugsource", rpm:"mod_auth_openidc-debugsource~2.4.17.2~1.fc41", rls:"FC41"))) {
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
