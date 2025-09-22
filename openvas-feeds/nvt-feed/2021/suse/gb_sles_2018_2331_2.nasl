# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2331.2");
  script_cve_id("CVE-2018-3639", "CVE-2018-3640", "CVE-2018-3646");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-16 18:57:03 +0000 (Thu, 16 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2331-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2331-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182331-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104134");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004716.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security update to ucode-intel' package(s) announced via the SUSE-SU-2018:2331-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ucode-intel was updated to the 20180807 release.

For the listed CPU chipsets this fixes CVE-2018-3640 (Spectre v3a) and is part of the mitigations for CVE-2018-3639 (Spectre v4) and CVE-2018-3646
(L1 Terminal fault).
(bsc#1104134 bsc#1087082 bsc#1087083 bsc#1089343)

 Processor Identifier Version Products

 Model Stepping F-MO-S/PI Old->New

 ---- new platforms ----------------------------------------
 WSM-EP/WS U1 6-2c-2/03 0000001f Xeon E/L/X56xx, W36xx
 NHM-EX D0 6-2e-6/04 0000000d Xeon E/L/X65xx/75xx
 BXT C0 6-5c-2/01 00000014 Atom T5500/5700
 APL E0 6-5c-a/03 0000000c Atom x5-E39xx
 DVN B0 6-5f-1/01 00000024 Atom C3xxx
 ---- updated platforms ------------------------------------
 NHM-EP/WS D0 6-1a-5/03 00000019->0000001d Xeon E/L/X/W55xx
 NHM B1 6-1e-5/13 00000007->0000000a Core i7-8xx, i5-7xx, Xeon L3426, X24xx
 WSM B1 6-25-2/12 0000000e->00000011 Core i7-6xx, i5-6xx/4xxM, i3-5xx/3xxM, Pentium G69xx, Celeon P45xx, Xeon L3406
 WSM K0 6-25-5/92 00000004->00000007 Core i7-6xx, i5-6xx/5xx/4xx, i3-5xx/3xx, Pentium G69xx/P6xxx/U5xxx, Celeron P4xxx/U3xxx
 SNB D2 6-2a-7/12 0000002d->0000002e Core Gen2, Xeon E3
 WSM-EX A2 6-2f-2/05 00000037->0000003b Xeon E7
 IVB E2 6-3a-9/12 0000001f->00000020 Core Gen3 Mobile
 HSW-H/S/E3 Cx/Dx 6-3c-3/32 00000024->00000025 Core Gen4 Desktop, Xeon E3 v3
 BDW-U/Y E/F 6-3d-4/c0 0000002a->0000002b Core Gen5 Mobile
 HSW-ULT Cx/Dx 6-45-1/72 00000023->00000024 Core Gen4 Mobile and derived Pentium/Celeron
 HSW-H Cx 6-46-1/32 00000019->0000001a Core Extreme i7-5xxxX
 BDW-H/E3 E/G 6-47-1/22 0000001d->0000001e Core i5-5xxxR/C, i7-5xxxHQ/EQ, Xeon E3 v4
 SKL-U/Y D0 6-4e-3/c0 000000c2->000000c6 Core Gen6 Mobile
 BDX-DE V1 6-56-2/10 00000015->00000017 Xeon D-1520/40
 BDX-DE V2/3 6-56-3/10 07000012->07000013 Xeon D-1518/19/21/27/28/31/33/37/41/48, Pentium D1507/08/09/17/19
 BDX-DE Y0 6-56-4/10 0f000011->0f000012 Xeon D-1557/59/67/71/77/81/87
 APL D0 6-5c-9/03 0000002c->00000032 Pentium N/J4xxx, Celeron N/J3xxx, Atom x5/7-E39xx
 SKL-H/S/E3 R0 6-5e-3/36 000000c2->000000c6 Core Gen6, Xeon E3 v5");

  script_tag(name:"affected", value:"'Security update to ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20180807~13.29.1", rls:"SLES12.0SP2"))) {
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
