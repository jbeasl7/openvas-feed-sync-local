# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0195.1");
  script_cve_id("CVE-2012-5668", "CVE-2012-5669");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0195-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0195-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130195-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2013:0195-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes:

 * OOB access in bdf_free_font() and _bdf_parse_glyphs()
(CVE-2012-5668 and CVE-2012-5669)

As well as the following non-security bugs:

 * [bdf] Savannah bug #37905. o src/bdf/bdflib.c
(_bdf_parse_start): Reset `props_size' to zero in case of allocation error, this value gets used in a loop in
 * [bdf] Fix Savannah bug #37906. o src/bdf/bdflib.c
(_bdf_parse_glyphs): Use correct array size for checking
`glyph_enc'.

Security Issue references:

 * CVE-2012-5668
>
 * CVE-2012-5669
>");

  script_tag(name:"affected", value:"'freetype2' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.3.7~25.32.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-32bit", rpm:"freetype2-32bit~2.3.7~25.32.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-x86", rpm:"freetype2-x86~2.3.7~25.32.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ft2demos", rpm:"ft2demos~2.3.7~25.32.1", rls:"SLES11.0SP2"))) {
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
