# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0998.1");
  script_cve_id("CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 15:09:07 +0000 (Mon, 13 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0998-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0998-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210998-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177380");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-March/008574.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the SUSE-SU-2021:0998-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opensc fixes the following issues:

- CVE-2020-26571: gemsafe GPK smart card software driver stack-based buffer overflow (bsc#1177380)
- CVE-2019-15946: out-of-bounds access of an ASN.1 Octet string in asn1_decode_entry (bsc#1149747)
- CVE-2019-15945: out-of-bounds access of an ASN.1 Bitstring in decode_bit_string (bsc#1149746)
- CVE-2019-19479: incorrect read operation during parsing of a SETCOS file attribute (bsc#1158256)
- CVE-2020-26572: Prevent out of bounds write (bsc#1177378)
- CVE-2020-26570: Fix buffer overflow in sc_oberthur_read_file (bsc#1177364)");

  script_tag(name:"affected", value:"'opensc' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.13.0~3.11.1", rls:"SLES12.0SP5"))) {
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
