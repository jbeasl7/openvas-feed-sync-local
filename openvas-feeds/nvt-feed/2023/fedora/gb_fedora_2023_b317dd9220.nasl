# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885173");
  script_cve_id("CVE-2023-42118");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:17 +0000 (Sun, 05 Nov 2023)");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-07 18:17:31 +0000 (Thu, 07 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2023-b317dd9220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b317dd9220");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-b317dd9220");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241536");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241537");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libspf2' package(s) announced via the FEDORA-2023-b317dd9220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Patch CVE-2023-42118, plus some other fixes.");

  script_tag(name:"affected", value:"'libspf2' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"libspf2", rpm:"libspf2~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspf2-apidocs", rpm:"libspf2-apidocs~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspf2-debuginfo", rpm:"libspf2-debuginfo~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspf2-debugsource", rpm:"libspf2-debugsource~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspf2-devel", rpm:"libspf2-devel~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspf2-progs", rpm:"libspf2-progs~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspf2-progs-debuginfo", rpm:"libspf2-progs-debuginfo~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SPF_XS", rpm:"perl-Mail-SPF_XS~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SPF_XS-debuginfo", rpm:"perl-Mail-SPF_XS-debuginfo~1.2.11~11.20210922git4915c308.fc39", rls:"FC39"))) {
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
