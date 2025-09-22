# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131103");
  script_cve_id("CVE-2015-7747");
  script_tag(name:"creation_date", value:"2015-10-26 07:36:02 +0000 (Mon, 26 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-28 20:33:26 +0000 (Fri, 28 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0408");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0408.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/10/08/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16923");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audiofile' package(s) announced via the MGASA-2015-0408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When libaudiofile is used to change both the number of channels of an
audio file (e.g. from stereo to mono) and the sample format (e.g. from
16-bit samples to 8-bit samples), the output file will contain corrupted
data. If the new sample format is smaller than the old one, there is a
risk of buffer overflow: e.g. when the input file has 16-bit samples and
the output file has 8-bit samples, afReadFrames will treat the buffer to
read the samples (argument void *data) as a pointer to int16_t instead of
int8_t, therefore it will write past its end (CVE-2015-7747).");

  script_tag(name:"affected", value:"'audiofile' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"audiofile", rpm:"audiofile~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiofile-devel", rpm:"lib64audiofile-devel~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64audiofile1", rpm:"lib64audiofile1~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiofile-devel", rpm:"libaudiofile-devel~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudiofile1", rpm:"libaudiofile1~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
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
