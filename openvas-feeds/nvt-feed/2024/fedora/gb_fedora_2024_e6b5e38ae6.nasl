# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.101698510138971016");
  script_cve_id("CVE-2024-23984", "CVE-2024-24968");
  script_tag(name:"creation_date", value:"2024-09-17 04:09:13 +0000 (Tue, 17 Sep 2024)");
  script_version("2024-09-17T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-09-17 05:05:45 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-e6b5e38ae6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e6b5e38ae6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e6b5e38ae6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283214");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2311299");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2024-e6b5e38ae6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-45. 20240910
 - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
 0x35 up to 0x36,
 - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
 intel-ucode/06-97-02) from revision 0x35 up to 0x36,
 - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
 from revision 0x35 up to 0x36,
 - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
 from revision 0x35 up to 0x36,
 - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
 intel-ucode/06-97-05) from revision 0x35 up to 0x36,
 - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x35
 up to 0x36,
 - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
 from revision 0x35 up to 0x36,
 - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
 from revision 0x35 up to 0x36,
 - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
 0x433 up to 0x434,
 - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
 intel-ucode/06-9a-03) from revision 0x433 up to 0x434,
 - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
 intel-ucode/06-9a-04) from revision 0x433 up to 0x434,
 - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x433
 up to 0x434,
 - Update of 06-aa-04/0xe6 (MTL-H/U C0) microcode from revision 0x1e
 up to 0x1f,
 - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x123 up
 to 0x129,
 - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
 0x4121 up to 0x4122,
 - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
 intel-ucode/06-ba-02) from revision 0x4121 up to 0x4122,
 - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) from
 revision 0x4121 up to 0x4122,
 - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
 intel-ucode/06-ba-03) from revision 0x4121 up to 0x4122,
 - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4121
 up to 0x4122,
 - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) from
 revision 0x4121 up to 0x4122,
 - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
 intel-ucode/06-ba-08) from revision 0x4121 up to 0x4122,
 - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
 intel-ucode/06-ba-08) from revision 0x4121 up to 0x4122,
 - Update of 06-ba-08/0xe0 microcode from revision 0x4121 up to 0x4122,
 - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
 intel-ucode/06-bf-02) from revision 0x35 up to 0x36,
 - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
 intel-ucode/06-bf-02) from revision 0x35 up to 0x36,
 - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x35 up
 to 0x36,
 - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
 from revision 0x35 up to 0x36,
 - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
 intel-ucode/06-bf-05) from revision 0x35 up to 0x36,
 - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~61.3.fc40", rls:"FC40"))) {
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
