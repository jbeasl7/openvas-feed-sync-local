# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885261");
  script_cve_id("CVE-2023-47272");
  script_tag(name:"creation_date", value:"2023-11-16 02:16:11 +0000 (Thu, 16 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:22:50 +0000 (Tue, 14 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-cf584ed77a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cf584ed77a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-cf584ed77a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248088");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248089");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the FEDORA-2023-cf584ed77a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Release 1.6.5**

- Fix PHP8 fatal error when parsing a malformed BODYSTRUCTURE (#9171)
- Fix duplicated Inbox folder on IMAP servers that do not use Inbox folder with all capital letters (#9166)
- Fix PHP warnings (#9174)
- Fix UI issue when dealing with an invalid managesieve_default_headers value (#9175)
- Fix bug where images attached to application/smil messages weren't displayed (#8870)
- Fix PHP string replacement error in utils/error.php (#9185)
- Fix regression where `smtp_user` did not allow pre/post strings before/after `%u` placeholder (#9162)
- Fix cross-site scripting (XSS) vulnerability in setting Content-Type/Content-Disposition for attachment preview/download");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.5~1.fc39", rls:"FC39"))) {
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
