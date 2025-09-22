# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.879973");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2021-3622");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-10 13:37:00 +0000 (Mon, 10 Jan 2022)");
  script_tag(name:"creation_date", value:"2021-08-18 07:56:54 +0000 (Wed, 18 Aug 2021)");
  script_name("Fedora: Security Advisory for hivex (FEDORA-2021-372d83d54e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-372d83d54e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/USD4OEV6L3RPHE32V2MJ4JPFBODINWSU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hivex'
  package(s) announced via the FEDORA-2021-372d83d54e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hive files are the undocumented binary files that Windows uses to
store the Windows Registry on disk.  Hivex is a library that can read
and write to these files.

&#39, hivexsh&#39, is a shell you can use to interactively navigate a hive
binary file.

&#39, hivexregedit&#39, (in perl-hivex) lets you export and merge to the
textual regedit format.

&#39, hivexml&#39, can be used to convert a hive file to a more useful XML
format.

In order to get access to the hive files themselves, you can copy them
from a Windows machine.  They are usually found in
%systemroot%\system32\config.  For virtual machines we recommend
using libguestfs or guestfish to copy out these files.  libguestfs
also provides a useful high-level tool called &#39, virt-win-reg&#39, (based on
hivex technology) which can be used to query specific registry keys in
an existing Windows VM.

For OCaml bindings, see 'ocaml-hivex-devel'.

For Perl bindings, see 'perl-hivex'.

For Python 3 bindings, see 'python3-hivex'.

For Ruby bindings, see 'ruby-hivex'.");

  script_tag(name:"affected", value:"'hivex' package(s) on Fedora 34.");

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

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"hivex", rpm:"hivex~1.3.21~1.fc34", rls:"FC34"))) {
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
