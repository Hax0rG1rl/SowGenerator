# SowGenerator
Serpico plugin to support generating statement of work documents instead of reports.

# Install
clone in your Serpico plugins directory.


# Engineering Notes:
DataMapper cannot create tables from the model when utilizing a repository namespace that is different from default. This is probably a bug in DataMapper. Create the tables manually:

```
CREATE TABLE "services" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "type" VARCHAR(200) NOT NULL, "title" VARCHAR(200), "report_id" INTEGER NOT NULL, "master_id" INTEGER, "service_modified" BOOLEAN, "units" INTEGER, "rate" INTEGER, "description" VARCHAR(20000), "notes" VARCHAR(20000));
CREATE TABLE "template_services" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "type" VARCHAR(200) NOT NULL, "title" VARCHAR(200), "units" INTEGER, "rate" INTEGER, "description" VARCHAR(20000));
CREATE TABLE "xslt_sows" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "xslt_id" INTEGER NOT NULL);
```
