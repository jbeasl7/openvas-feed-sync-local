# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123157");
  script_cve_id("CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0696)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0696");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0696.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the ELSA-2015-0696 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.3.11-15.el6_6.1]
- Fixes CVE-2014-9657
 - Check minimum size of record_size.
- Fixes CVE-2014-9658
 - Use correct value for minimum table length test.
- Fixes CVE-2014-9675
 - New macro that checks one character more than strncmp.
- Fixes CVE-2014-9660
 - Check _BDF_GLYPH_BITS.
- Fixes CVE-2014-9661
 - Initialize face->ttf_size.
 - Always set face->ttf_size directly.
 - Exclusively use the truetype font driver for loading
 the font contained in the sfnts array.
- Fixes CVE-2014-9663
 - Fix order of validity tests.
- Fixes CVE-2014-9664
 - Add another boundary testing.
 - Fix boundary testing.
- Fixes CVE-2014-9667
 - Protect against addition overflow.
- Fixes CVE-2014-9669
 - Protect against overflow in additions and multiplications.
- Fixes CVE-2014-9670
 - Add sanity checks for row and column values.
- Fixes CVE-2014-9671
 - Check size and offset values.
- Fixes CVE-2014-9673
 - Fix integer overflow by a broken POST table in resource-fork.
- Fixes CVE-2014-9674
 - Fix integer overflow by a broken POST table in resource-fork.
 - Additional overflow check in the summation of POST fragment lengths.
- Work around behaviour of X11s pcfWriteFont and pcfReadFont functions
- Resolves: #1197737

[2.3.11-15]
- Fix CVE-2012-5669
 (Use correct array size for checking glyph_enc)
- Resolves: #903543");

  script_tag(name:"affected", value:"'freetype' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.3.11~15.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.3.11~15.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.3.11~15.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.4.11~10.el7_1.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.4.11~10.el7_1.1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.4.11~10.el7_1.1", rls:"OracleLinux7"))) {
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
