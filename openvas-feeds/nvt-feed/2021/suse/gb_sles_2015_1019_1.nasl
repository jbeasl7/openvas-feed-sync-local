# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1019.1");
  script_cve_id("CVE-2015-1196", "CVE-2015-1395", "CVE-2015-1396");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-09 15:01:09 +0000 (Mon, 09 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1019-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1019-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151019-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915329");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-June/001427.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the SUSE-SU-2015:1019-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The GNU patch utility was updated to 2.7.5 to fix three security issues and one non-security bug.

The following vulnerabilities were fixed:

* CVE-2015-1196: directory traversal flaw when handling git-style patches. This could allow an attacker to overwrite arbitrary files by tricking the user into applying a specially crafted patch. (bsc#913678)
* CVE-2015-1395: directory traversal flaw when handling patches which rename files. This could allow an attacker to overwrite arbitrary files by tricking the user into applying a specially crafted patch. (bsc#915328)
* CVE-2015-1396: directory traversal flaw via symbolic links. This could allow an attacker to overwrite arbitrary files by tricking the user into applying a by applying a specially crafted patch. (bsc#915329)

The following bug was fixed:

* bsc#904519: Function names in hunks (from diff -p) are now preserved in reject files.");

  script_tag(name:"affected", value:"'patch' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.5~7.1", rls:"SLES12.0"))) {
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
