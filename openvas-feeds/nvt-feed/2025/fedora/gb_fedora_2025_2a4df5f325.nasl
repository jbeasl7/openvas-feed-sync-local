# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.29741001025102325");
  script_cve_id("CVE-2025-40907");
  script_tag(name:"creation_date", value:"2025-06-06 04:08:30 +0000 (Fri, 06 Jun 2025)");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-2a4df5f325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-2a4df5f325");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-2a4df5f325");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366847");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366914");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-FCGI' package(s) announced via the FEDORA-2025-2a4df5f325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This release fixes an integer and heap buffer overflow when processing a user FastCGI request.");

  script_tag(name:"affected", value:"'perl-FCGI' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-FCGI", rpm:"perl-FCGI~0.82~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-FCGI-debuginfo", rpm:"perl-FCGI-debuginfo~0.82~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-FCGI-debugsource", rpm:"perl-FCGI-debugsource~0.82~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-FCGI-tests", rpm:"perl-FCGI-tests~0.82~13.fc41", rls:"FC41"))) {
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
