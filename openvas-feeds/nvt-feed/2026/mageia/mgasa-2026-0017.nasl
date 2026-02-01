# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0017");
  script_cve_id("CVE-2025-40214", "CVE-2025-40248", "CVE-2025-40250", "CVE-2025-40251", "CVE-2025-40252", "CVE-2025-40253", "CVE-2025-40254", "CVE-2025-40257", "CVE-2025-40258", "CVE-2025-40259", "CVE-2025-40261", "CVE-2025-40262", "CVE-2025-40263", "CVE-2025-40264", "CVE-2025-40266", "CVE-2025-40268", "CVE-2025-40269", "CVE-2025-40271", "CVE-2025-40272", "CVE-2025-40273", "CVE-2025-40275", "CVE-2025-40277", "CVE-2025-40278", "CVE-2025-40279", "CVE-2025-40280", "CVE-2025-40281", "CVE-2025-40282", "CVE-2025-40283", "CVE-2025-40284", "CVE-2025-40285", "CVE-2025-40286", "CVE-2025-40288", "CVE-2025-40292", "CVE-2025-40293", "CVE-2025-40294", "CVE-2025-40297", "CVE-2025-40301", "CVE-2025-40303", "CVE-2025-40304", "CVE-2025-40306", "CVE-2025-40308", "CVE-2025-40309", "CVE-2025-40310", "CVE-2025-40311", "CVE-2025-40312", "CVE-2025-40313", "CVE-2025-40314", "CVE-2025-40315", "CVE-2025-40316", "CVE-2025-40317", "CVE-2025-40318", "CVE-2025-40319", "CVE-2025-40320", "CVE-2025-40321", "CVE-2025-40322", "CVE-2025-40323", "CVE-2025-40324", "CVE-2025-40328", "CVE-2025-40329", "CVE-2025-40331", "CVE-2025-40333", "CVE-2025-40337", "CVE-2025-40341", "CVE-2025-40342", "CVE-2025-40343", "CVE-2025-40345", "CVE-2025-40358", "CVE-2025-40360", "CVE-2025-40361", "CVE-2025-40363", "CVE-2025-68168", "CVE-2025-68171", "CVE-2025-68172", "CVE-2025-68173", "CVE-2025-68176", "CVE-2025-68177", "CVE-2025-68178", "CVE-2025-68179", "CVE-2025-68183", "CVE-2025-68184", "CVE-2025-68185", "CVE-2025-68191", "CVE-2025-68192", "CVE-2025-68194", "CVE-2025-68198", "CVE-2025-68200", "CVE-2025-68204", "CVE-2025-68208", "CVE-2025-68214", "CVE-2025-68217", "CVE-2025-68218", "CVE-2025-68219", "CVE-2025-68220", "CVE-2025-68222", "CVE-2025-68224", "CVE-2025-68227", "CVE-2025-68229", "CVE-2025-68231", "CVE-2025-68233", "CVE-2025-68235", "CVE-2025-68237", "CVE-2025-68238", "CVE-2025-68241", "CVE-2025-68244", "CVE-2025-68245", "CVE-2025-68246", "CVE-2025-68282", "CVE-2025-68283", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68286", "CVE-2025-68287", "CVE-2025-68288", "CVE-2025-68289", "CVE-2025-68290", "CVE-2025-68291", "CVE-2025-68295", "CVE-2025-68297", "CVE-2025-68301", "CVE-2025-68302", "CVE-2025-68303", "CVE-2025-68305", "CVE-2025-68307", "CVE-2025-68308", "CVE-2025-68310", "CVE-2025-68312", "CVE-2025-68320", "CVE-2025-68321", "CVE-2025-68327", "CVE-2025-68328", "CVE-2025-68330", "CVE-2025-68331", "CVE-2025-68339", "CVE-2025-68342", "CVE-2025-68343", "CVE-2025-68369", "CVE-2025-68734", "CVE-2025-68767", "CVE-2025-68769", "CVE-2025-68771", "CVE-2025-68772", "CVE-2025-68773", "CVE-2025-68774", "CVE-2025-68775", "CVE-2025-68776", "CVE-2025-68777", "CVE-2025-68778", "CVE-2025-68780", "CVE-2025-68781", "CVE-2025-68782", "CVE-2025-68783", "CVE-2025-68785", "CVE-2025-68786", "CVE-2025-68787", "CVE-2025-68788", "CVE-2025-68789", "CVE-2025-68794", "CVE-2025-68795", "CVE-2025-68796", "CVE-2025-68797", "CVE-2025-68798", "CVE-2025-68799", "CVE-2025-68800", "CVE-2025-68801", "CVE-2025-68804", "CVE-2025-68806", "CVE-2025-68808", "CVE-2025-68809", "CVE-2025-68813", "CVE-2025-68814", "CVE-2025-68815", "CVE-2025-68816", "CVE-2025-68817", "CVE-2025-68818", "CVE-2025-68819", "CVE-2025-68820", "CVE-2025-68821", "CVE-2025-71064", "CVE-2025-71065", "CVE-2025-71066", "CVE-2025-71067", "CVE-2025-71068", "CVE-2025-71069", "CVE-2025-71071", "CVE-2025-71075", "CVE-2025-71077", "CVE-2025-71078", "CVE-2025-71079", "CVE-2025-71081", "CVE-2025-71082", "CVE-2025-71083", "CVE-2025-71084", "CVE-2025-71085", "CVE-2025-71086", "CVE-2025-71087", "CVE-2025-71088", "CVE-2025-71089", "CVE-2025-71091", "CVE-2025-71093", "CVE-2025-71094", "CVE-2025-71095", "CVE-2025-71096", "CVE-2025-71097", "CVE-2025-71098", "CVE-2025-71101", "CVE-2025-71102", "CVE-2025-71104", "CVE-2025-71105", "CVE-2025-71107", "CVE-2025-71108", "CVE-2025-71111", "CVE-2025-71112", "CVE-2025-71113", "CVE-2025-71114", "CVE-2025-71116", "CVE-2025-71118", "CVE-2025-71119", "CVE-2025-71120", "CVE-2025-71121", "CVE-2025-71122", "CVE-2025-71123", "CVE-2025-71125", "CVE-2025-71126", "CVE-2025-71127", "CVE-2025-71129", "CVE-2025-71130", "CVE-2025-71131", "CVE-2025-71132", "CVE-2025-71133", "CVE-2025-71136", "CVE-2025-71137", "CVE-2025-71138", "CVE-2025-71140", "CVE-2025-71141", "CVE-2025-71143", "CVE-2025-71144");
  script_tag(name:"creation_date", value:"2026-01-26 04:30:45 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-26T05:50:34+0000");
  script_tag(name:"last_modification", value:"2026-01-26 05:50:34 +0000 (Mon, 26 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0017");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0017.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35021");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.117");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.118");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.119");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2026-0017 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upstream kernel version 6.6.120 fixes bugs and vulnerabilities.
The kmod-virtualbox & kmod-xtables-addons packages have been updated to
work with this new kernel.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586", rpm:"kernel-desktop586~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel", rpm:"kernel-desktop586-devel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server", rpm:"kernel-server~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel", rpm:"kernel-server-devel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.1.14~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.24~88.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf1", rpm:"lib64bpf1~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf1", rpm:"libbpf1~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.6.120~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-6.6.120-desktop-1.mga9", rpm:"virtualbox-kernel-6.6.120-desktop-1.mga9~7.1.14~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-6.6.120-server-1.mga9", rpm:"virtualbox-kernel-6.6.120-server-1.mga9~7.1.14~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.1.14~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.1.14~14.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.120-desktop-1.mga9", rpm:"xtables-addons-kernel-6.6.120-desktop-1.mga9~3.24~88.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.120-desktop586-1.mga9", rpm:"xtables-addons-kernel-6.6.120-desktop586-1.mga9~3.24~88.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.120-server-1.mga9", rpm:"xtables-addons-kernel-6.6.120-server-1.mga9~3.24~88.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.24~88.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.24~88.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.24~88.mga9", rls:"MAGEIA9"))) {
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
