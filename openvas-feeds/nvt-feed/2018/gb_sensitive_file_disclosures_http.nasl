# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107305");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2018-04-20 16:04:01 +0200 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  # nb: A CVSSv2 score above is used which is not necessarily the scoring attached to the CVEs below.
  #     This was done on purpose as some might have some too high or wrong scoring
  script_cve_id("CVE-2017-16894");
  script_name("Sensitive File Disclosure (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl",
                      "gb_drupal_http_detect.nasl", "sw_magento_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files containing sensitive data
  at the remote web server.");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if sensitive files
  are accessible.");

  script_tag(name:"insight", value:"Currently the script is checking for files like e.g.:

  - Software (Blog, CMS) configuration or log files

  - Web / application server configuration / password files (.htaccess, .htpasswd, web.config,
  web.xml, ...)

  - Cloud (e.g. AWS) configuration files

  - Files containing API keys for services / providers

  - Database backup files

  - Editor / history files

  - SSH or SSL/TLS Private Keys

  - CVE-2017-16894: Laravel framework environment/.env files");

  script_tag(name:"impact", value:"Based on the information provided in these files an attacker
  might be able to gather additional info and/or sensitive data like usernames and passwords.");

  script_tag(name:"solution", value:"The sensitive files shouldn't be accessible via a web server.
  Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

# nb:
# - We can't save an array within an array so we're using:
#   array index = the file to check
#   array value =
#   - the description and the regex (case sensitive) of the checked file separated with #-#
#   - optional a third entry separated by #-# containing an "extra_check" regex (also case sensitive)
#   - optional a fourth entry separated by #-# containing an "extra_check" regex (also case sensitive)
# - To make sure that we're not using two or more entries for the same file in this array (When e.g.
#   having two entries the foreach(keys()) loop would iterate over both items but the infos variable
#   in both iterations would only include the info from one of both entries two times) we can use
#   something like e.g. the following:
#   egrep -o '^"[^"]+",' 2018/gb_sensitive_file_disclosures_http.nasl | sort | uniq -d
#
genericfiles = make_array(

  "/local.properties", "Generic properties (may contain sensitive configuration information) / Allaire JRUN configuration (could contain sensitive information about the structure of the application / web server) file accessible.#-#^(#Properties File|\s*(perfmon\.installDir|apple\.awt\.graphics\.Use(OpenGL|Quartz))\s*=.+|\s*\[?(file\.browsedirs=(false|true)|users\.location=.+))",

  # https://git-scm.com/docs/git-credential-store#_storage_format
  # nb: Unclear if e.g. also https://<username>:@example.com is possible so the "[^@]*" regex has been
  # used to allow / support this for now.
  "/.git-credentials", "Git Credential Storage File containing a username and/or password.#-#^\s*https?://[^:]+:[^@]*@.+",
  "/git/credentials", "Git Credential Storage File containing a username and/or password.#-#^\s*https?://[^:]+:[^@]*@.+",
  "/.config/git/credentials", "Git Credential Storage File containing a username and/or password.#-#^\s*https?://[^:]+:[^@]*@.+",

  "/.idea/WebServers.xml", 'IntelliJ Platform Configuration File containing a username and/or password.#-#<component name="WebServers">#-#(password|username)=',

  # see e.g. https://symfony.com/legacy/doc/reference/1_2/en/07-databases
  "/config/databases.yml", "Symfony Framework Database Configuration File containing a username and/or password.#-#^\s*(param|class)\s*:#-#^\s*(username|password)\s*:",
  "/app/config/config.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
  "/app/config/config_dev.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
  "/app/config/config_prod.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
  "/app/config/config_test.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",

  # See https://symfony.com/doc/current/logging.html, e.g.:
  # [2020-05-06 19:14:00] request.ERROR: Uncaught PHP Exception Symfony\Component\HttpKernel\Exception\NotFoundHttpException:
  # [2017-04-21 17:50:02] event.DEBUG: Notified event "console.command" to listener
  "/app/logs/prod.log", "Symfony Framework log file.#-#^\[[^]]+\]\s+[^.]+\.(ERROR|NOTICE|INFO|DEBUG):\s+",
  "/app/logs/dev.log", "Symfony Framework log file.#-#^\[[^]]+\]\s+[^.]+\.(ERROR|NOTICE|INFO|DEBUG):\s+",

  # https://guides.rubyonrails.org/configuring.html#configuring-a-database
  # https://guides.rubyonrails.org/configuring.html#connection-preference
  # nb: "production", "development" and "test" seems to be "fixed" strings:
  # > The config/database.yml file contains sections for three different environments in which Rails can run by default:
  "/config/database.yml", "Ruby on Rails Database Configuration File containing sensitive info like a username, password, URL and/or hostname.#-#^\s*(production|development|test)\s*:\s*$#-#^\s*(username|password|url|host)\s*:.+",

  "/DEADJOE", 'Editor JOE created the file DEADJOE on crash, which contains content of the currently edited files.#-#JOE (when it|was) aborted',
  "/server.key", "SSL/TLS Private Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC|ENCRYPTED|OPENSSH)? ?PRIVATE KEY",
  "/privatekey.key", "SSL/TLS Private Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC|ENCRYPTED|OPENSSH)? ?PRIVATE KEY",
  "/myserver.key", "SSL/TLS Private Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC|ENCRYPTED|OPENSSH)? ?PRIVATE KEY",
  "/key.pem", "SSL/TLS Private Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC|ENCRYPTED|OPENSSH)? ?PRIVATE KEY",

  # Some examples for private key names can be seen at e.g.:
  # https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#Local_Account_Public_/_Private_Key_Pairs
  "/id_rsa", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_dsa", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (DSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_dss", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (DSS|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_ecdsa", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_ed25519", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_ecdsa-sk", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_ed25519-sk", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_ecdsa-sk_rk", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_ed25519-sk_rk", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  # Additional ones seen in examples / guides like e.g.:
  # https://cryptomonkeys.com/2015/04/generating-ssh-keys/
  "/id_rsa_1024", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_rsa_2048", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_rsa_3072", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
  "/id_rsa_4096", "SSH Private Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",

  # https://laravel.com/docs/master/configuration#environment-configuration
  # https://blog.quickadminpanel.com/how-to-use-laravel-env-example-files/
  # nb: There is also a check for .env.$hostname separately created further down
  "/.env", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_1", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.backup", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.bak", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_baremetal", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.development.local", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.dev", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.dev.local", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.example", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_hosted", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.live", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.local", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_local", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.old", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.prod", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.prod.local", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.production", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_production", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.production.local", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_sample", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.save", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.stage", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env_staging", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.env.www", 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.local", 'Laravel config file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.production", 'Laravel config file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/.remote", 'Laravel config file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/staging2.env.example", 'Laravel config file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/env.example", 'Laravel config file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+',
  "/app/config/parameters.yml", "Contao CMS, PrestaShop or Symfony Framework Database Configuration File containing a username and/or password.#-#(^\s*parameters\s*:|This file is auto-generated during the composer install)#-#^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:",
  "/config.development.json", 'Ghost Database Configuration File containing a username and/or password.#-#"database" ?:#-#"(user|password)"',
  "/config.production.json", 'Ghost Database Configuration File containing a username and/or password.#-#"database" ?:#-#"(user|password)"',

  # https://docs.djangoproject.com/en/2.0/ref/settings/
  # https://stackoverflow.com/questions/7382149/whats-the-purpose-of-django-setting-secret-key
  # Basically these should be found:
  # 'USER': 'mydatabaseuser',
  # 'PASSWORD': 'mypassword',
  # SECRET_KEY = 'django-insecure <actual secret key>'
  "/settings.py", "Django Configuration File containing a SECRET_KEY or a username and/or password.#-#^\s*(SECRET_KEY\s*=|'(USER|PASSWORD)'\s*:)\s*'[^']+'",
  "/global_settings.py", "Django Configuration File containing a SECRET_KEY or a username and/or password.#-#^\s*(SECRET_KEY\s*=|'(USER|PASSWORD)'\s*:)\s*'[^']+'",

  # https://blog.dewhurstsecurity.com/2018/06/07/database-sql-backup-files-alexa-top-1-million.html
  # https://github.com/hannob/snallygaster/blob/a423d4063f37763f9288505c0baca69e216daa7c/snallygaster#L352-L355
  "/dump.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/database.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/1.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/backup.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/data.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/db_backup.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/dbdump.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/db.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/localhost.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/mysql.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/site.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/sql.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/temp.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/users.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/translate.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
  "/mysqldump.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',

  # e.g.
  # {"php":"7.2.4-1+ubuntu16.04.1+deb.sury.org+1","version":"2.11.1:v2.11.1#ad94441c17b8ef096e517acccdbf3238af8a2da8","rules":{"binary_operator_spaces":true,"blank_line_after_opening_tag":true,"blank_line_before_statement":{"statements":
  # {"php":"5.6.26-1+deb.sury.org~xenial+1","version":"2.0.0","rules":{"array_syntax":{"syntax":"short"},"combine_consecutive_unsets":true,"general_phpdoc_annotation_remove":
  # nb: Different file names are v2 (the first one) vs. v3 (the second one)
  "/.php_cs.cache", 'Cache file .php_cs.cache of PHP-CS-Fixer could expose a listing of PHP files.#-#^\\{"php":"#-#"(version|rules|binary_operator_spaces|blank_line_after_opening_tag|blank_line_before_statement|array_syntax|syntax|statements)":"',
  "/.php-cs-fixer.cache", 'Cache file .php-cs-fixer.cache of PHP-CS-Fixer could expose a listing of PHP files.#-#^\\{"php":"#-#"(version|rules|binary_operator_spaces|blank_line_after_opening_tag|blank_line_before_statement|array_syntax|syntax|statements)":"',

  # Example: https://github.com/Flexberry/javascript-project-template/blob/master/.coveralls.yml.example
  "/.coveralls.yml", "Coveralls Configuration File containing a secret repo token for a repository accessible.#-#^repo_token\s*:.+",

  # Example syntax:
  # https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
  # https://wiki.selfhtml.org/wiki/Webserver/htaccess/Passwortschutz
  # https://httpd.apache.org/docs/2.4/howto/auth.html
  "/.htpasswd", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.htpasswd-users", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.htpasswd-all", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.htpasswds", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.htuser", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.htusers", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.access", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.passwd", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
  "/.htaccess", "Apache HTTP Server .htaccess file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*(<Directory [^>]+>|</Directory>|</?RequireAll>|Require (group |user |valid-user|ldap-group |all |not host |not ip)|GroupName: |Auth(Type|Name|BasicProvider|LDAPURL|(User|Group|DBMUser)File) )",

  # https://docs.microsoft.com/en-us/iis-administration/security/integrated/web.config
  # https://docs.microsoft.com/en-us/troubleshoot/aspnet/create-web-config
  "/web.config", "Microsoft IIS / ASP.NET Core Module web.config file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(configuration|system\.web(Server)?)>#-#^\s*</(configuration|system\.web(Server)?)>",

  "/WEB-INF/web.xml", "Configuration file of various application servers (Apache Tomcat, Mort Bay/Eclipse Jetty, ...) accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)#-#^\s*</(web-app|servlet)>$",
  "/META-INF/web.xml", "Configuration file of various application servers (Apache Tomcat, Mort Bay/Eclipse Jetty, ...) accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)#-#^\s*</(web-app|servlet)>$",
  "/web.xml", "Configuration file of various application servers (Apache Tomcat, Mort Bay/Eclipse Jetty, ...) accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)#-#^\s*</(web-app|servlet)>$",
  "/WEB-INF/webapp.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
  "/webapp.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
  # nb: There is one check for a "local.properties" file without a dir on top of this array...
  "/WEB-INF/local.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
  "/service.cnf", "Microsoft IIS / SharePoint / FrontPage configuration file#-#^vti_[^:]+:[A-Z]{2}\|.+",

  # https://linux.die.net/man/5/esmtprc
  "/.esmtprc", "esmtp configuration file containing a username and password#-#^\s*username\s*=.+#-#^\s*password\s*=.+",

  # https://framework.zend.com/manual/1.12/en/zend.application.quick-start.html
  # https://framework.zend.com/manual/1.12/en/zend.application.available-resources.html
  # https://github.com/feibeck/application.ini/blob/master/application.ini
  "/application/configs/application.ini", "Zend Framework configuration file#-#^\s*;?\s*(phpSettings|pluginpaths|resources\.(db|cachemanager|dojo|frontController|layout|locale|log|mail|modules|navigation|session|view|jQuery)|bootstrap)\.[^=]+=.+#-#^\s*\[.*production\]",
  "/configs/application.ini", "Zend Framework configuration file#-#^\s*;?\s*(phpSettings|pluginpaths|resources\.(db|cachemanager|dojo|frontController|layout|locale|log|mail|modules|navigation|session|view|jQuery)|bootstrap)\.[^=]+=.+#-#^\s*\[.*production\]",

  # https://blog.robomongo.org/robo-3t-1-3/ has some examples
  "/robomongo.json", 'RoboMongo / Robo 3T configuration file that may contain sensitive configuration information.#-#^\\s*"(userName|userPassword(Encrypted)?|databaseName|serverHost)"\\s*:\\s*"[^"]+"',
  "/robo3T.json", 'RoboMongo / Robo 3T configuration file that may contain sensitive configuration information.#-#^\\s*"(userName|userPassword(Encrypted)?|databaseName|serverHost)"\\s*:\\s*"[^"]+"',
  "/robo3t.json", 'RoboMongo / Robo 3T configuration file that may contain sensitive configuration information.#-#^\\s*"(userName|userPassword(Encrypted)?|databaseName|serverHost)"\\s*:\\s*"[^"]+"',

  # https://airflow.apache.org/docs/apache-airflow/stable/howto/set-config.html
  "/airflow.cfg", "Apache Airflow file that may contain sensitive configuration information.#-#^\s*\[core\]#-#^\s*\[(api|celery|atlas|smtp|webserver)\]",

  # https://book.cakephp.org/phinx/0/en/configuration.html
  "/phinx.yml", "Phinx configuration file containing database configuration info.#-#^\s*environments:#-#^\s*(host|name|user|pass):.+",
  "/phinx.yaml", "Phinx configuration file containing database configuration info.#-#^\s*environments:#-#^\s*(host|name|user|pass):.+",
  "/phinx.json", 'Phinx configuration file containing database configuration info.#-#^\\s*"environments":#-#^\\s*"(host|name|user|pass)":.+',

  # https://github.com/dodiksunaryo/qdpm/blob/master/core/config/databases.yml.sample
  "/core/config/databases.yml", "qdPM configuration file containing database configuration info.#-#^\s*dsn:.+#-#^\s*(username|password):.+",
  "/databases.yml", "qdPM configuration file containing database configuration info.#-#^\s*dsn:.+#-#^\s*(username|password):.+",

  # See e.g.
  # https://docs.mongodb.com/manual/reference/mongo-shell/
  # https://docs.mongodb.com/manual/reference/program/mongo/#std-label-mongo-dbshell-file
  "/.dbshell", "MongoDB .dbshell history file containing used database commands.#-#^(show (collections|users|roles|profile|databases)$|db\.(collection\..+|(load|auth|getCollectionNames|dropDatabase)\(\)|(run|admin)Command))#-#",

  # Symfony Security Configuration, see the links below for examples:
  # https://symfony2-document.readthedocs.io/en/latest/book/security.html
  # https://symfony.com/doc/current/reference/configuration/security.html
  "/config/packages/security.yaml", "Symfony 'security.yml' may contain sensitive configuration information.#-#^\s*security\s*:\s*$#-#^\s*(firewalls|access_control|providers|encoders)\s*:\s*$",
  "/app/config/security.yml", "Symfony 'security.yml' may contain sensitive configuration information.#-#^\s*security\s*:\s*$#-#^\s*(firewalls|access_control|providers|encoders)\s*:\s*$",

  # From e.g.:
  # - https://github.com/liuxiaoping910818/ssm/blob/master/src/main/resources/config.properties
  # - https://github.com/TuiQiao/CBoard/blob/v0.4.1/src/main/resources/config.properties
  "/config.properties", "General Java .properties configuration file containing database and/or SMTP configuration info.#-#^\s*(jdbc_|mail\.smtp\.)username\s*=.+#-#^\s*(jdbc_|mail\.smtp\.)password\s*=.+#-#^\s*(jdbc_url|mail\.smtp\.(host|ssl\.checkserveridentity)|driverClassName|validationQuery)\s*=.+",

  # From e.g..
  # - 2021/lanproxy_project/gb_lanproxy_dir_trav_vuln_jan21.nasl
  # - https://github.com/maybe-why-not/lanproxy/issues/1
  # but there might be more of such product using the same syntax...
  "/conf/config.properties", "LanProxy (or similar product) .properties configuration file containing credentials.#-#^\s*(config\.admin\.(username|password)|server\.ssl\.key(Manager|Store)Password)\s*=.+",

  # e.g.
  # - https://github.com/misskiki/MysqlLogmonitor/blob/master/mysql_config.ini
  # - https://levelup.gitconnected.com/tips-and-tricks-for-handling-sql-in-python-via-pymysql-49ee738c0abf?gi=c812cec6ee8e
  "/mysql_config.ini", 'MySQL configuration file containing database configuration info.#-#^\\s*user(name)?(=|":).+#-#^\\s*pass(word)?(=|":).+#-#^\\s*(port|host|db(_)?name)(=|":).+',

  # https://dev.mysql.com/doc/refman/8.0/en/mysql-config-editor.html
  "/.mylogin.cnf", "mysql_config_editor configuration file containing database configuration info.#-#^\s*user\s*=.+#-#^\s*password\s*=.+#-#^\s*host\s*=.+",

  # https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials_profiles.html
  # https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html
  # https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-authentication.html
  "/.aws/credentials", "AWS credentials file which might contain sensitive access keys.#-#^\[[^]]+\]\s*$#-#^(aws_access_key_id|aws_secret_access_key|role_arn|source_profile|role_session_name)\s*=.+",
  "/.aws/config", "AWS profile file which might contain sensitive application info.#-#^\[[^]]+\]\s*$#-#^(role_arn|source_profile|role_session_name)\s*=.+",

  # https://sendgrid.com/blog/dont-let-your-credentials-get-stolen-on-github/
  # https://docs.sendgrid.com/ui/account-and-settings/api-keys (includes the info on the length on the API key)
  # https://stackoverflow.com/questions/42030912/how-to-get-the-full-sendgrid-api-key (Example for an API key)
  "/sendgrid.env", "Twilio SendGrid API key, more info on https://sendgrid.com/blog/dont-let-your-credentials-get-stolen-on-github/#-#(SENDGRID_API_KEY.+|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})",

  # From:
  # - https://unix.stackexchange.com/a/246641 (Info on the syntax)
  # - https://unix.stackexchange.com/a/246631 (Info on the locations, see LESSHISTFILE on "man less" as well)
  "/.lesshst", "'less' history file#-#^\.less-history-file:\s*$",
  "/_lesshst", "'less' history file#-#^\.less-history-file:\s*$",
  "/lesshst.ini", "'less' history file#-#^\.less-history-file:\s*$",

  # From https://twitter.com/therceman/status/1704560089309257868
  # nb: Seems the `_wpeprivate` folder can exist on an arbitrary sub-folder so it was added here and
  # not to "rootdirfiles" or a specific WordPress check
  "/_wpeprivate/config.json", 'WPEngine configuration file, https://twitter.com/therceman/status/1704560089309257868#-#\\{"env"\\s*:\\s*\\{.*"(WPENGINE_(ACCOUNT|SESSION_DB_USERNAME|SESSION_DB_PASSWORD)|wpengine_apikey)"\\s*:\\s*"[^"]+"',

  # Various examples available in https://vite.dev/config/
  "/vite.config.js", "Vite configuration file#-#^export default [^{]*\{#-#^\}",

  # Examples can be seen in https://code.visualstudio.com/docs/debugtest/debugging-configuration#_launch-configurations
  "/.vscode/launch.json", 'Visual Studio Code / VC Code debug configuration file which might contain sensitive information.#-#^\\s*"version"\\s*:\\s*"[^"]*"\\s*,#-#^\\s*"configurations"\\s*:\\s*\\['
);

# https://doc.nette.org/en/configuring or https://github.com/nette/examples/blob/master/CD-collection/app/config.neon
foreach nettedir( make_list( "/app/config", "/app", "" ) ) {
  genericfiles[nettedir + "/config.neon"] = "Nette Framework config file is publicly accessible.#-#^((php|application|database|services|security|latte|session|extensions):|# SECURITY WARNING: it is CRITICAL)#-#^ *((date\.timezone|mapping|dsn|debugger|users|roles|resources|errorPresenter|catchExceptions|silentLinks|user|password|macros):|- App)";
}

# Add domain specific key names and backup files from above
hnlist = create_hostname_parts_list();

# nb: No need to check for an empty "hn" string here (create_hostname_parts_list() could return an
# empty list) as foreach seems to be able to handle this.
foreach hn( hnlist ) {
  genericfiles["/" + hn + ".key"] = "SSL/TLS Private Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC|ENCRYPTED|OPENSSH)? ?PRIVATE KEY";
  genericfiles["/" + hn + ".pem"] = "SSL/TLS Private Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC|ENCRYPTED|OPENSSH)? ?PRIVATE KEY";
  genericfiles["/" + hn + ".sql"] = "Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )";
  genericfiles["/env." + hn ] = 'Laravel ".env" file present that may contain sensitive information like database credentials.#-#^(APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)|DB_(HOST|USERNAME|PASSWORD|DATABASE))=.+';
}

# nb: The ones which should be checked only on the "root" level ("/") of the target system.
rootdirfiles = make_array(
  # See e.g. https://insecure.org/sploits/Microsoft.frontpage.insecurities.html or http://sparty.secniche.org/
  "/_vti_pvt/service.pwd", "Microsoft FrontPage .pwd Credentials file is publicly accessible.#-#^# -FrontPage-",
  "/_vti_pvt/administrators.pwd", "Microsoft FrontPage .pwd Credentials file is publicly accessible.#-#^# -FrontPage-",
  "/_vti_pvt/authors.pwd", "Microsoft FrontPage .pwd Credentials file is publicly accessible.#-#^# -FrontPage-"
);

magentofiles = make_array(
  "/app/etc/local.xml", 'Magento 1 Database Configuration File containing a username and/or password.#-#(<config|Mage)#-#<(username|password)>'
);

drupalfiles = make_array(
  "/sites/default/private/files/backup_migrate/scheduled/test.txt", 'If the file "test.txt" is accessible on a Drupal server, it means that site backups may be publicly exposed.#-#this file should not be publicly accessible',
  "/sites/default/files/.ht.sqlite", "Drupal Database file publicly accessible.#-#^SQLite format [0-9]"
);

global_var report, VULN;

function check_files( filesarray, dirlist, port ) {

  local_var filesarray, dirlist, port;
  local_var dir, file, infos, desc, pattern, extra, url;

  foreach dir( dirlist ) {

    if( dir == "/" )
      dir = "";

    foreach file( keys( filesarray ) ) {

      if( ! infos = filesarray[file] )
        continue;

      # infos[0] contains the description, infos[1] the regex. Optionally infos[2] (and possibly
      # infos[3] if defined) contains additional extra checks as defined below.
      infos = split( infos, sep:"#-#", keep:FALSE );
      if( max_index( infos ) < 2 )
        continue; # Something is wrong with the provided info...

      desc = infos[0];
      pattern = infos[1];

      # nb: Just resetting these so that don't have these defined from the previous loop iteration.
      extra1 = NULL;
      extra_match1 = NULL;
      extra2 = NULL;
      extra_match2 = NULL;

      if( strlen( infos[2] ) > 0 )
        extra1 = infos[2];

      if( strlen( infos[3] ) > 0 )
        extra2 = infos[3];

      url = dir + file;

      res = http_get_cache( port:port, item:url );

      # nb: If false positives are reported at some point in the future we might want to check for a
      # "Content-Type: text/html" and continue here if this is included.
      if( ! res || res !~ "^HTTP/1\.[01] 200" )
        continue;

      res = http_extract_body_from_response( data:res );
      res = chomp( res );
      if( ! res )
        continue;

      found = FALSE;

      if( match = egrep( string:res, pattern:pattern, icase:FALSE ) )
        found = TRUE;

      if( found && extra1 ) {
        # nb: Just resetting it back so that we're only reporting if the "extra" match below
        # is also matching.
        found = FALSE;
        if( extra_match1 = egrep( string:res, pattern:extra1, icase:FALSE ) )
          found = TRUE;
      }

      if( found && extra2 ) {
        # nb: Resetting for the same reason given previously...
        found = FALSE;
        if( extra_match2 = egrep( string:res, pattern:extra2, icase:FALSE ) )
          found = TRUE;
      }

      if( found ) {
        report += '\n\nDescription:   ' + desc;
        report += '\nMatch:         ' + chomp( match );
        report += '\nUsed regex:    ' + pattern;

        if( extra_match1 ) {
          report += '\nExtra match 1: ' + chomp( extra_match1 );
          report += '\nUsed regex:    ' + extra1;
        }

        if( extra_match2 ) {
          report += '\nExtra match 2: ' + chomp( extra_match2 );
          report += '\nUsed regex:    ' + extra2;
        }

        report += '\nURL:           ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        VULN = TRUE;
      }
    }
  }
}

report = "The following files containing sensitive information were identified:";

port = http_get_port( default:80 );

dirlist = make_list_unique( "/", http_cgi_dirs( port:port ) );
check_files( filesarray:genericfiles, dirlist:dirlist, port:port );

check_files( filesarray:rootdirfiles, dirlist:make_list( "/" ), port:port );

drdirs = get_app_location( port:port, cpe:"cpe:/a:drupal:drupal", nofork:TRUE );
if( drdirs )
  drupaldirlist = make_list_unique( drdirs, dirlist );
else
  drupaldirlist = dirlist;
check_files( filesarray:drupalfiles, dirlist:drupaldirlist, port:port );

madirs = get_app_location( port:port, cpe:"cpe:/a:magentocommerce:magento", nofork:TRUE );
if( madirs )
  magentodirlist = make_list_unique( madirs, dirlist );
else
  magentodirlist = dirlist;
check_files( filesarray:magentofiles, dirlist:magentodirlist, port:port );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
