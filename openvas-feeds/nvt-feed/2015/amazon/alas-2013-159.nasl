# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120239");
  script_cve_id("CVE-2011-4355");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:11 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-159)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-159");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-159.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the ALAS-2013-159 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GDB tried to auto-load certain files (such as GDB scripts, Python scripts, and a thread debugging library) from the current working directory when debugging programs. This could result in the execution of arbitrary code with the user's privileges when GDB was run in a directory that has untrusted content. (CVE-2011-4355)

With this update, GDB no longer auto-loads files from the current directory and only trusts certain system directories by default. The list of trusted directories can be viewed and modified using the 'show auto-load safe-path' and 'set auto-load safe-path' GDB commands. Refer to the GDB manual, linked to in the References, for further information.");

  script_tag(name:"affected", value:"'gdb' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~7.2~60.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debuginfo", rpm:"gdb-debuginfo~7.2~60.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-gdbserver", rpm:"gdb-gdbserver~7.2~60.13.amzn1", rls:"AMAZON"))) {
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
